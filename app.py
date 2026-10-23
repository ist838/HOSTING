import os
import hmac
import json
import hashlib
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, abort, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

DATABASE = os.environ.get("DATABASE_PATH", "hosting.db")
WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")

PLANS = {
    "free": {
        "name": "무료",
        "price": 0,
        "bot_limit": 1,
    },
    "pro": {
        "name": "프리미엄",
        "price": 5000,
        "bot_limit": 4,
    },
    "unlimited": {
        "name": "무제한",
        "price": 50000,
        "bot_limit": None,
    },
}


def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                subscription_status TEXT NOT NULL DEFAULT 'inactive',
                subscription_id TEXT,
                period_end TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL
            )
        """)


init_db()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def bot_limit_for(user):
    if not user:
        return 1

    plan = user["plan"]
    if plan not in PLANS:
        return 1

    # 유료 플랜은 결제가 활성 상태일 때만 적용
    if plan != "free" and user["subscription_status"] != "active":
        return 1

    return PLANS[plan]["bot_limit"]


PAGE = """
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>봇 호스팅</title>
<style>
body{font-family:Arial,sans-serif;max-width:760px;margin:30px auto;padding:0 16px}
input,button{padding:10px;margin:5px 0;max-width:100%}
.card{border:1px solid #ddd;border-radius:12px;padding:16px;margin:12px 0}
a{margin-right:10px}
</style>
</head>
<body>
<h1>디스코드 봇 호스팅</h1>
{% with messages = get_flashed_messages() %}
  {% for message in messages %}<p>{{ message }}</p>{% endfor %}
{% endwith %}
{{ content|safe }}
</body>
</html>
"""


def page(content, **context):
    return render_template_string(PAGE, content=render_template_string(
        content, **context
    ))


@app.route("/")
def index():
    user = current_user()
    if not user:
        return page("""
        <p>디스코드 봇 호스팅 사이트입니다.</p>
        <a href="{{ url_for('register') }}">회원가입</a>
        <a href="{{ url_for('login') }}">로그인</a>
        <a href="{{ url_for('pricing') }}">요금제</a>
        """)

    with db() as conn:
        bots = conn.execute(
            "SELECT * FROM bots WHERE user_id = ? ORDER BY id DESC",
            (user["id"],)
        ).fetchall()

    limit = bot_limit_for(user)
    limit_text = "무제한" if limit is None else str(limit)
    return page("""
    <p>회원: <b>{{ user['username'] }}</b></p>
    <p>요금제: {{ PLANS[user['plan']]['name'] }}</p>
    <p>구독 상태: {{ user['subscription_status'] }}</p>
    <p>봇: {{ bots|length }} / {{ limit_text }}</p>
    <form method="post" action="{{ url_for('create_bot') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <input name="name" maxlength="50" placeholder="봇 프로젝트 이름" required>
      <button>봇 프로젝트 만들기</button>
    </form>
    <h2>내 봇 프로젝트</h2>
    {% for bot in bots %}
      <div class="card">{{ bot['name'] }}</div>
    {% else %}
      <p>아직 프로젝트가 없습니다.</p>
    {% endfor %}
    <p><a href="{{ url_for('pricing') }}">요금제 변경</a>
    <a href="{{ url_for('logout') }}">로그아웃</a></p>
    """, user=user, bots=bots, limit_text=limit_text,
       PLANS=PLANS, csrf=csrf_token())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    token = request.form.get("csrf", "")
    if not hmac.compare_digest(token, session.get("csrf", "")):
        abort(400, "잘못된 요청입니다. 페이지를 새로고침하세요.")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 30 or len(password) < 8:
            flash("아이디는 3~30자, 비밀번호는 8자 이상이어야 합니다.")
        else:
            try:
                with db() as conn:
                    conn.execute(
                        "INSERT INTO users (username,password_hash) VALUES (?,?)",
                        (username, generate_password_hash(password))
                    )
                flash("가입되었습니다. 로그인해 주세요.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("이미 사용 중인 아이디입니다.")

    return page("""
    <h2>회원가입</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <p><input name="username" placeholder="아이디" required></p>
      <p><input type="password" name="password" placeholder="비밀번호(8자 이상)" required></p>
      <button>가입하기</button>
    </form>
    """, csrf=csrf_token())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))

        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return page("""
    <h2>로그인</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <p><input name="username" placeholder="아이디" required></p>
      <p><input type="password" name="password" placeholder="비밀번호" required></p>
      <button>로그인</button>
    </form>
    """, csrf=csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/pricing")
def pricing():
    user = current_user()
    return page("""
    <h2>월 구독 요금제</h2>
    {% for key, plan in PLANS.items() %}
      <div class="card">
        <h3>{{ plan['name'] }}</h3>
        <p>{{ "{:,}".format(plan['price']) }}원 / 월</p>
        <p>
        {% if plan['bot_limit'] is none %}
          봇 프로젝트 개수 제한 없음
        {% else %}
          봇 프로젝트 최대 {{ plan['bot_limit'] }}개
        {% endif %}
        </p>
        {% if key == 'free' %}
          <p>무료 플랜은 회원가입 후 기본 적용됩니다.</p>
        {% elif user %}
          <form method="post" action="{{ url_for('subscribe', plan_key=key) }}">
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <button>구독 신청</button>
          </form>
        {% else %}
          <a href="{{ url_for('login') }}">로그인 후 구독 신청</a>
        {% endif %}
      </div>
    {% endfor %}
    <p><a href="{{ url_for('index') }}">돌아가기</a></p>
    """, PLANS=PLANS, user=user, csrf=csrf_token())


@app.route("/subscribe/<plan_key>", methods=["POST"])
@login_required
def subscribe(plan_key):
    check_csrf()

    if plan_key not in ("pro", "unlimited"):
        abort(400, "잘못된 요금제입니다.")

    # 실제 결제창과 연결되기 전에는 유료 등급을 활성화하지 않음.
    # 결제 업체의 공식 SDK/API로 구독을 생성한 뒤 결제 페이지로
    # 이동시키는 코드를 이 위치에 연결해야 함.
    return page("""
    <h2>결제 연결이 필요합니다</h2>
    <p>{{ plan_name }} 월 구독을 선택했습니다.</p>
    <p>아직 결제 업체가 연결되지 않아 결제가 진행되지 않았습니다.
       결제 완료 전에는 유료 기능이 활성화되지 않습니다.</p>
    <a href="{{ url_for('pricing') }}">요금제로 돌아가기</a>
    """, plan_name=PLANS[plan_key]["name"])


@app.route("/bots/create", methods=["POST"])
@login_required
def create_bot():
    check_csrf()
    user = current_user()
    name = request.form.get("name", "").strip()

    if not name or len(name) > 50:
        flash("프로젝트 이름은 1~50자로 입력해 주세요.")
        return redirect(url_for("index"))

    with db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM bots WHERE user_id = ?",
            (user["id"],)
        ).fetchone()["n"]

        limit = bot_limit_for(user)
        if limit is not None and count >= limit:
            flash("현재 요금제의 봇 개수 제한에 도달했습니다.")
            return redirect(url_for("pricing"))

        conn.execute(
            "INSERT INTO bots (user_id,name,created_at) VALUES (?,?,?)",
            (user["id"], name, datetime.now(timezone.utc).isoformat())
        )

    flash("봇 프로젝트가 생성되었습니다.")
    return redirect(url_for("index"))


@app.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    """
    예시용 HMAC Webhook.
    실제 PG 업체의 서명 검증 방식과 이벤트 필드에 맞게 수정해야 합니다.

    이 예시는 다음 JSON 형식을 가정합니다.
    {
      "event_id": "고유 이벤트 ID",
      "type": "subscription.activated",
      "username": "회원 아이디",
      "plan": "pro",
      "subscription_id": "구독 ID",
      "period_end": "2027-01-01T00:00:00+00:00"
    }

    헤더 X-Webhook-Signature:
      HMAC-SHA256(원본 요청 본문, PAYMENT_WEBHOOK_SECRET)의 hex 값
    """
    if not WEBHOOK_SECRET:
        abort(503, "Webhook 비밀키가 설정되지 않았습니다.")

    raw = request.get_data()
    signature = request.headers.get("X-Webhook-Signature", "")
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), raw, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        abort(400, "Webhook 서명이 올바르지 않습니다.")

    try:
        event = json.loads(raw)
    except (ValueError, TypeError):
        abort(400, "JSON 형식이 올바르지 않습니다.")

    event_id = str(event.get("event_id", ""))
    event_type = event.get("type")
    username = event.get("username")
    plan = event.get("plan")
    subscription_id = event.get("subscription_id")
    period_end = event.get("period_end")

    if not event_id or not username:
        abort(400, "이벤트 ID 또는 회원 정보가 없습니다.")

    with db() as conn:
        # 중복 Webhook 이벤트 처리 방지
        try:
            conn.execute(
                "INSERT INTO webhook_events(event_id,received_at) VALUES (?,?)",
                (event_id, datetime.now(timezone.utc).isoformat())
            )
        except sqlite3.IntegrityError:
            return {"ok": True, "duplicate": True}

        if event_type == "subscription.activated":
            if plan not in ("pro", "unlimited") or not subscription_id:
                abort(400, "구독 정보가 올바르지 않습니다.")

            conn.execute("""
                UPDATE users
                SET plan=?, subscription_status='active',
                    subscription_id=?, period_end=?
                WHERE username=?
            """, (plan, subscription_id, period_end, username))

        elif event_type in (
            "subscription.canceled",
            "subscription.expired",
            "subscription.payment_failed",
        ):
            # 실제 서비스에서는 PG의 상태를 재조회하고,
            # 유예 기간 및 현재 결제 주기를 확인한 뒤 변경해야 합니다.
            conn.execute("""
                UPDATE users
                SET plan='free', subscription_status='inactive',
                    subscription_id=NULL
                WHERE username=?
            """, (username,))

    return {"ok": True}



@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>디스코드 봇 호스팅</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f4f5f8;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                box-sizing: border-box;
            }
            .card {
                background: white;
                max-width: 420px;
                width: 100%;
                padding: 32px 24px;
                border-radius: 18px;
                text-align: center;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
                box-sizing: border-box;
            }
            h1 { font-size: 26px; }
            p {
                color: #666;
                line-height: 1.8;
            }
            .status {
                display: inline-block;
                background: #fff0d5;
                color: #8a5700;
                padding: 8px 14px;
                border-radius: 20px;
                margin-bottom: 12px;
            }
        </style>
    </head>
    <body>
        <main class="card">
            <div class="status">서비스 준비 중</div>
            <h1>아직 준비되지 않았습니다.</h1>
            <p>
                디스코드 봇 호스팅 사이트를 준비하고 있습니다.<br>
                조금만 기다려 주세요!
            </p>
        </main>
    </body>
    </html>
    """)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
