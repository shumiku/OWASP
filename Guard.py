from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from groq import Groq
from sqlalchemy import create_engine, text
from typing import Optional
import hashlib
import hmac
import json
import os
import re
import secrets
import time

app = FastAPI(title="LLM GUARD API")

MODEL_NAME = "openai/gpt-oss-120b"

# ==================================
# 1. CORS 跨來源設定
# ==================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================
# 2. PostgreSQL 資料庫設定
# ==================================

db_url = os.environ.get("DATABASE_URL")

engine = None

if db_url:

    # 相容部分雲端平台提供的 PostgreSQL URL
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)

    elif db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

    try:
        engine = create_engine(
            db_url,
            pool_pre_ping=True
        )
        print("PostgreSQL 資料庫設定完成")

    except Exception as e:
        print("Database Error:", str(e))

else:
    print("Warning: DATABASE_URL is not set.")


def need_db():
    if not engine:
        raise HTTPException(
            status_code=503,
            detail="資料庫尚未設定（DATABASE_URL）"
        )


# ==================================
# 3. 密碼雜湊（PBKDF2-HMAC-SHA256，鹽值由伺服器產生）
# ==================================

PBKDF2_ROUNDS = 200_000
SESSION_HOURS = 12
MAX_FAIL = 5
LOCK_SECONDS = 30
MAX_PROGRESS_BYTES = 200_000
MAX_NOTES_BYTES = 300_000

NAME_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fff]{3,20}$")


def hash_password(pwd: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(pwd: str, stored: str) -> bool:
    try:
        _, rounds, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", pwd.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# 帳號不存在時也做一次運算，避免從回應時間推測帳號是否存在
DUMMY_HASH = hash_password("dummy-password-for-timing")

# ---- 註冊驗證與復原碼設定（皆可用環境變數調整）----
REGISTER_CODE = os.environ.get("REGISTER_CODE", "").strip()          # 設定後，註冊時必須輸入這組註冊碼（由老師提供）
REGISTER_LIMIT = int(os.environ.get("REGISTER_LIMIT", "10"))         # 同一個 IP 每小時最多註冊幾個帳號
RESET_LIMIT = int(os.environ.get("RESET_LIMIT", "10"))               # 同一個 IP 每小時最多嘗試幾次重設密碼
RECOVERY_MAX_FAIL = 5
RECOVERY_LOCK_SECONDS = 600
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"                # 去掉容易看錯的 I O 0 1

_RATE = {}


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, limit: int, window: int = 3600):
    """簡易的記憶體計數器：超過次數就回傳 429（單一主機適用）。"""
    now = time.time()
    hits = [t for t in _RATE.get(bucket, []) if now - t < window]
    if len(hits) >= limit:
        raise HTTPException(status_code=429, detail="嘗試次數過多，請稍後再試。")
    hits.append(now)
    _RATE[bucket] = hits
    if len(_RATE) > 5000:
        for k in [k for k, v in _RATE.items() if not v or now - v[-1] > window]:
            _RATE.pop(k, None)


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_recovery(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", code or "").upper()


def set_recovery(conn, key: str) -> str:
    """產生新的復原碼並存入雜湊（舊的立即失效），回傳明文，只會顯示一次。"""
    code = new_recovery_code()
    conn.execute(
        text("""
            UPDATE users SET recovery_hash = :h, recovery_fail = 0, recovery_locked_until = NULL
            WHERE username_key = :k
        """),
        {"h": hash_password(normalize_recovery(code)), "k": key}
    )
    return code


def check_username(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="帳號需為 3～20 字，只能使用中英文、數字與底線。"
        )
    return name


def check_password(pwd: str) -> str:
    pwd = pwd or ""
    if len(pwd) < 8:
        raise HTTPException(status_code=400, detail="密碼至少 8 個字元。")
    if len(pwd) > 64:
        raise HTTPException(status_code=400, detail="密碼最多 64 個字元。")
    if not re.search(r"[A-Za-z]", pwd) or not re.search(r"\d", pwd):
        raise HTTPException(status_code=400, detail="密碼需要同時包含英文字母與數字。")
    return pwd


# ==================================
# 4. 資料表建立與預設帳號
# ==================================

def init_db():
    if not engine:
        return

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    username_key  VARCHAR(40) PRIMARY KEY,
                    display_name  VARCHAR(40) NOT NULL,
                    role          VARCHAR(10) NOT NULL CHECK (role IN ('user','admin')),
                    password_hash TEXT NOT NULL,
                    failed_count  INT NOT NULL DEFAULT 0,
                    locked_until  TIMESTAMPTZ,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_login    TIMESTAMPTZ
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash   TEXT PRIMARY KEY,
                    username_key VARCHAR(40) NOT NULL
                        REFERENCES users(username_key) ON DELETE CASCADE,
                    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at   TIMESTAMPTZ NOT NULL
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS progress (
                    username_key VARCHAR(40) PRIMARY KEY
                        REFERENCES users(username_key) ON DELETE CASCADE,
                    data         JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            # 復原碼欄位（舊資料庫也會自動補上）
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash TEXT"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_fail INT NOT NULL DEFAULT 0"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_locked_until TIMESTAMPTZ"))
            # 筆記與書籤：只有本人讀得到（管理者的 API 不會回傳這張表）
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notes (
                    username_key VARCHAR(40) PRIMARY KEY
                        REFERENCES users(username_key) ON DELETE CASCADE,
                    data         JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))

            has_admin = conn.execute(
                text("SELECT count(*) FROM users WHERE role = 'admin'")
            ).scalar()
            has_any = conn.execute(text("SELECT count(*) FROM users")).scalar()

            if not has_admin:
                # 正式上線請在環境變數設定 ADMIN_USER / ADMIN_PASSWORD
                admin_user = os.environ.get("ADMIN_USER", "admin")
                admin_pass = os.environ.get("ADMIN_PASSWORD", "Admin@2026")
                conn.execute(
                    text("""
                        INSERT INTO users (username_key, display_name, role, password_hash)
                        VALUES (:k, :n, 'admin', :h)
                        ON CONFLICT (username_key) DO NOTHING
                    """),
                    {"k": admin_user.lower(), "n": "系統管理者", "h": hash_password(admin_pass)}
                )

            if not has_any:
                conn.execute(
                    text("""
                        INSERT INTO users (username_key, display_name, role, password_hash)
                        VALUES (:k, :n, 'user', :h)
                        ON CONFLICT (username_key) DO NOTHING
                    """),
                    {
                        "k": os.environ.get("DEMO_USER", "student").lower(),
                        "n": "示範學員",
                        "h": hash_password(os.environ.get("DEMO_PASSWORD", "Student@2026")),
                    }
                )

        print("資料表檢查完成（users / sessions / progress / notes）")

    except Exception as e:
        print("Init DB Error:", str(e))


@app.on_event("startup")
def on_startup():
    init_db()


# ==================================
# 5. 登入驗證（Bearer Token）
# ==================================

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_user(authorization: Optional[str] = Header(None)):
    need_db()

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="請先登入。")

    th = token_hash(authorization[7:].strip())

    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT u.username_key, u.display_name, u.role
                FROM sessions s
                JOIN users u ON u.username_key = s.username_key
                WHERE s.token_hash = :h AND s.expires_at > now()
            """),
            {"h": th}
        ).mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="登入已過期，請重新登入。")

    return {
        "user": row["username_key"],
        "name": row["display_name"],
        "role": row["role"],
        "token_hash": th,
    }


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理者可以執行這個操作。")
    return user


def public_user(u):
    return {"user": u["user"], "name": u["name"], "role": u["role"]}


# ==================================
# 6. 資料格式
# ==================================

class ChatRequest(BaseModel):
    message: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    invite: str = ""


class ResetRequest(BaseModel):
    username: str
    recovery_code: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class PasswordOnlyRequest(BaseModel):
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class ProgressRequest(BaseModel):
    data: dict


class NotesRequest(BaseModel):
    data: dict


class AdminCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class PasswordRequest(BaseModel):
    password: str


# ==================================
# 7. API 健康檢查
# ==================================

@app.get("/")
def home():
    return {
        "status": "online",
        "message": "LLM GUARD API 正常運作"
    }


@app.get("/health")
def health():

    db_status = "not_configured"

    if engine:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            db_status = "connected"

        except Exception as e:
            db_status = "error"
            print("Database Connection Error:", str(e))

    return {
        "status": "healthy",
        "database": db_status
    }


# ==================================
# 8. 帳號：註冊 / 登入 / 登出 / 目前使用者
# ==================================

@app.get("/api/auth/config")
def auth_config():
    return {"status": "success", "register_code_required": bool(REGISTER_CODE)}


@app.post("/api/auth/register")
def register(req: RegisterRequest, request: Request):
    need_db()
    rate_limit("reg:" + client_ip(request), REGISTER_LIMIT)

    if REGISTER_CODE and not hmac.compare_digest((req.invite or "").strip(), REGISTER_CODE):
        raise HTTPException(status_code=403, detail="註冊碼不正確，請向老師索取。")

    name = check_username(req.username)
    check_password(req.password)
    key = name.lower()

    with engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM users WHERE username_key = :k"), {"k": key}
        ).first()

        if exists:
            raise HTTPException(status_code=409, detail="這個帳號名稱已被使用。")

        conn.execute(
            text("""
                INSERT INTO users (username_key, display_name, role, password_hash)
                VALUES (:k, :n, 'user', :h)
            """),
            {"k": key, "n": name, "h": hash_password(req.password)}
        )
        code = set_recovery(conn, key)

    return {
        "status": "success",
        "user": {"user": key, "name": name, "role": "user"},
        "recovery_code": code,
    }


@app.post("/api/auth/login")
def login(req: LoginRequest):
    need_db()

    key = (req.username or "").strip().lower()

    if not key or not req.password:
        raise HTTPException(status_code=400, detail="請輸入帳號與密碼。")

    failure = None

    with engine.begin() as conn:
        row = conn.execute(
            text("""
                SELECT username_key, display_name, role, password_hash,
                       CASE WHEN locked_until IS NOT NULL AND locked_until > now()
                            THEN CAST(EXTRACT(EPOCH FROM (locked_until - now())) AS INT) + 1
                            ELSE 0 END AS lock_left
                FROM users WHERE username_key = :k
            """),
            {"k": key}
        ).mappings().first()

        if row and row["lock_left"] > 0:
            raise HTTPException(
                status_code=429,
                detail=f"嘗試次數過多，請在 {row['lock_left']} 秒後再試。"
            )

        ok = verify_password(req.password, row["password_hash"] if row else DUMMY_HASH)

        if not row or not ok or row["role"] != req.role:
            failure = (401, "帳號、密碼或身分不正確。")

            if row:
                locked = conn.execute(
                    text("""
                        UPDATE users SET
                            failed_count = CASE WHEN failed_count + 1 >= :m THEN 0
                                                ELSE failed_count + 1 END,
                            locked_until = CASE WHEN failed_count + 1 >= :m
                                                THEN now() + (:s * interval '1 second')
                                                ELSE locked_until END
                        WHERE username_key = :k
                        RETURNING (locked_until IS NOT NULL AND locked_until > now())
                    """),
                    {"m": MAX_FAIL, "s": LOCK_SECONDS, "k": key}
                ).scalar()

                if locked:
                    failure = (429, f"嘗試次數過多，已暫時鎖定 {LOCK_SECONDS} 秒。")

        else:
            token = secrets.token_urlsafe(32)

            conn.execute(
                text("""
                    UPDATE users SET failed_count = 0, locked_until = NULL, last_login = now()
                    WHERE username_key = :k
                """),
                {"k": key}
            )
            conn.execute(text("DELETE FROM sessions WHERE expires_at < now()"))
            conn.execute(
                text("""
                    INSERT INTO sessions (token_hash, username_key, expires_at)
                    VALUES (:h, :k, now() + (:hrs * interval '1 hour'))
                """),
                {"h": token_hash(token), "k": key, "hrs": SESSION_HOURS}
            )

    # 注意：要在交易結束（已提交）之後才丟出錯誤，否則失敗次數的更新會被回滾，鎖定就不會生效
    if failure:
        raise HTTPException(status_code=failure[0], detail=failure[1])

    return {
        "status": "success",
        "token": token,
        "user": {"user": row["username_key"], "name": row["display_name"], "role": row["role"]},
    }


@app.post("/api/auth/logout")
def logout(user=Depends(current_user)):
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM sessions WHERE token_hash = :h"), {"h": user["token_hash"]}
        )
    return {"status": "success"}


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"status": "success", "user": public_user(user)}


# ---- 忘記密碼：用註冊時取得的復原碼重設（不需要 Email）----
@app.post("/api/auth/reset")
def reset_password(req: ResetRequest, request: Request):
    need_db()
    rate_limit("reset:" + client_ip(request), RESET_LIMIT)

    key = (req.username or "").strip().lower()
    code = normalize_recovery(req.recovery_code)
    check_password(req.new_password)

    if not key or len(code) < 16:
        raise HTTPException(status_code=400, detail="請輸入帳號與完整的復原碼。")

    generic = "帳號或復原碼不正確。如果你沒有復原碼，請聯絡管理者重設密碼。"
    failure = None
    new_code = None

    with engine.begin() as conn:
        row = conn.execute(
            text("""
                SELECT recovery_hash,
                       CASE WHEN recovery_locked_until IS NOT NULL AND recovery_locked_until > now()
                            THEN CAST(EXTRACT(EPOCH FROM (recovery_locked_until - now())) AS INT) + 1
                            ELSE 0 END AS lock_left
                FROM users WHERE username_key = :k AND role = 'user'
            """),
            {"k": key}
        ).mappings().first()

        if row and row["lock_left"] > 0:
            raise HTTPException(
                status_code=429,
                detail=f"嘗試次數過多，請在 {row['lock_left'] // 60 + 1} 分鐘後再試。"
            )

        stored = row["recovery_hash"] if row and row["recovery_hash"] else None
        ok = verify_password(code, stored or DUMMY_HASH)

        if not row or not stored or not ok:
            failure = generic

            if row:
                conn.execute(
                    text("""
                        UPDATE users SET
                            recovery_fail = CASE WHEN recovery_fail + 1 >= :m THEN 0 ELSE recovery_fail + 1 END,
                            recovery_locked_until = CASE WHEN recovery_fail + 1 >= :m
                                THEN now() + (:s * interval '1 second') ELSE recovery_locked_until END
                        WHERE username_key = :k
                    """),
                    {"m": RECOVERY_MAX_FAIL, "s": RECOVERY_LOCK_SECONDS, "k": key}
                )
        else:
            conn.execute(
                text("""
                    UPDATE users SET password_hash = :h, failed_count = 0, locked_until = NULL
                    WHERE username_key = :k
                """),
                {"h": hash_password(req.new_password), "k": key}
            )
            conn.execute(text("DELETE FROM sessions WHERE username_key = :k"), {"k": key})
            new_code = set_recovery(conn, key)       # 復原碼用過就換新的

    if failure:
        raise HTTPException(status_code=401, detail=failure)

    return {"status": "success", "recovery_code": new_code}


# ---- 已登入：修改密碼 / 重新產生復原碼 ----
@app.post("/api/auth/password")
def change_password(req: ChangePasswordRequest, user=Depends(current_user)):
    check_password(req.new_password)

    with engine.begin() as conn:
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE username_key = :k"),
            {"k": user["user"]}
        ).scalar()

        if not stored or not verify_password(req.old_password or "", stored):
            raise HTTPException(status_code=401, detail="目前的密碼不正確。")

        conn.execute(
            text("UPDATE users SET password_hash = :h WHERE username_key = :k"),
            {"h": hash_password(req.new_password), "k": user["user"]}
        )
        # 其他裝置的登入狀態一併失效，只保留目前這一個
        conn.execute(
            text("DELETE FROM sessions WHERE username_key = :k AND token_hash <> :t"),
            {"k": user["user"], "t": user["token_hash"]}
        )

    return {"status": "success"}


@app.post("/api/auth/recovery")
def regenerate_recovery(req: PasswordOnlyRequest, user=Depends(current_user)):
    with engine.begin() as conn:
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE username_key = :k"),
            {"k": user["user"]}
        ).scalar()

        if not stored or not verify_password(req.password or "", stored):
            raise HTTPException(status_code=401, detail="密碼不正確。")

        code = set_recovery(conn, user["user"])

    return {"status": "success", "recovery_code": code}


# ==================================
# 9. 學習進度（每個帳號一筆 JSONB）
# ==================================

@app.get("/api/progress")
def get_progress(user=Depends(current_user)):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT data FROM progress WHERE username_key = :k"),
            {"k": user["user"]}
        ).first()

    return {"status": "success", "data": row[0] if row else {}}


@app.put("/api/progress")
def save_progress(req: ProgressRequest, user=Depends(current_user)):
    payload = json.dumps(req.data, ensure_ascii=False)

    if len(payload.encode("utf-8")) > MAX_PROGRESS_BYTES:
        raise HTTPException(status_code=413, detail="進度資料過大。")

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO progress (username_key, data, updated_at)
                VALUES (:k, CAST(:d AS JSONB), now())
                ON CONFLICT (username_key)
                DO UPDATE SET data = CAST(:d AS JSONB), updated_at = now()
            """),
            {"k": user["user"], "d": payload}
        )

    return {"status": "success"}


# ==================================
# 9-2. 筆記與書籤（每個帳號一筆 JSONB，只有本人可讀寫）
# ==================================

@app.get("/api/notes")
def get_notes(user=Depends(current_user)):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT data FROM notes WHERE username_key = :k"),
            {"k": user["user"]}
        ).first()

    return {"status": "success", "data": row[0] if row else {}}


@app.put("/api/notes")
def save_notes(req: NotesRequest, user=Depends(current_user)):
    payload = json.dumps(req.data, ensure_ascii=False)

    if len(payload.encode("utf-8")) > MAX_NOTES_BYTES:
        raise HTTPException(status_code=413, detail="筆記內容過大，請精簡後再儲存。")

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO notes (username_key, data, updated_at)
                VALUES (:k, CAST(:d AS JSONB), now())
                ON CONFLICT (username_key)
                DO UPDATE SET data = CAST(:d AS JSONB), updated_at = now()
            """),
            {"k": user["user"], "d": payload}
        )

    return {"status": "success"}


# ==================================
# 10. 管理者：帳號與進度管理
# ==================================

@app.get("/api/admin/users")
def admin_list_users(admin=Depends(admin_user)):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT u.username_key AS ukey,
                   u.display_name AS dname,
                   u.role AS urole,
                   CAST(EXTRACT(EPOCH FROM u.last_login) * 1000 AS BIGINT) AS last_ms,
                   p.data AS progress
            FROM users u
            LEFT JOIN progress p ON p.username_key = u.username_key
            ORDER BY (u.role = 'admin') DESC, u.username_key
        """)).mappings().all()

    return {
        "status": "success",
        "users": [
            {
                "key": r["ukey"],
                "name": r["dname"],
                "role": r["urole"],
                "last": int(r["last_ms"]) if r["last_ms"] is not None else None,
                "progress": r["progress"] or {},
            }
            for r in rows
        ],
    }


@app.post("/api/admin/users")
def admin_create_user(req: AdminCreateRequest, admin=Depends(admin_user)):
    name = check_username(req.username)
    check_password(req.password)
    role = "admin" if req.role == "admin" else "user"
    key = name.lower()

    with engine.begin() as conn:
        if conn.execute(
            text("SELECT 1 FROM users WHERE username_key = :k"), {"k": key}
        ).first():
            raise HTTPException(status_code=409, detail="這個帳號名稱已被使用。")

        conn.execute(
            text("""
                INSERT INTO users (username_key, display_name, role, password_hash)
                VALUES (:k, :n, :r, :h)
            """),
            {"k": key, "n": name, "r": role, "h": hash_password(req.password)}
        )
        code = set_recovery(conn, key)

    return {"status": "success", "recovery_code": code}


@app.post("/api/admin/users/{key}/password")
def admin_reset_password(key: str, req: PasswordRequest, admin=Depends(admin_user)):
    check_password(req.password)
    key = key.lower()

    with engine.begin() as conn:
        done = conn.execute(
            text("""
                UPDATE users SET password_hash = :h, failed_count = 0, locked_until = NULL
                WHERE username_key = :k
            """),
            {"h": hash_password(req.password), "k": key}
        ).rowcount

        if not done:
            raise HTTPException(status_code=404, detail="找不到這個帳號。")

        # 重設密碼後，舊的登入狀態一併失效
        conn.execute(text("DELETE FROM sessions WHERE username_key = :k"), {"k": key})

    return {"status": "success"}


@app.delete("/api/admin/users/{key}/progress")
def admin_clear_progress(key: str, admin=Depends(admin_user)):
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM progress WHERE username_key = :k"), {"k": key.lower()}
        )
    return {"status": "success"}


@app.delete("/api/admin/users/{key}")
def admin_delete_user(key: str, admin=Depends(admin_user)):
    key = key.lower()

    if key == admin["user"]:
        raise HTTPException(status_code=400, detail="不能刪除自己目前登入的帳號。")

    with engine.begin() as conn:
        target = conn.execute(
            text("SELECT role FROM users WHERE username_key = :k"), {"k": key}
        ).first()

        if not target:
            raise HTTPException(status_code=404, detail="找不到這個帳號。")

        if target[0] == "admin":
            admins = conn.execute(
                text("SELECT count(*) FROM users WHERE role = 'admin'")
            ).scalar()
            if admins <= 1:
                raise HTTPException(status_code=400, detail="至少要保留一位管理者。")

        conn.execute(text("DELETE FROM users WHERE username_key = :k"), {"k": key})

    return {"status": "success"}


# ==================================
# 11-1. AI 助理的系統提示
# ==================================

SYSTEM_PROMPT = """你是專精於大型語言模型（LLM）安全與 OWASP 防禦機制的教學助理。請一律使用繁體中文回答。

【回答格式】
- 只用純文字回答，不要使用 Markdown 或 HTML 語法：不要出現 ** 、__ 、# 、` 、---、表格（| 符號）、<br> 等符號。
- 想條列時，每一點獨立一行，用「1.」「2.」或「・」開頭；想分段時，直接空一行。
- 不要自創小標題符號，也不要重複題目。回答精簡清楚，一般控制在 300 字內，使用者要求詳細時再展開。
- 如果使用者明確要求特定格式（例如只輸出 JSON），就照他的要求輸出，不受上述限制。

【OWASP Top 10 for LLM Applications 2025 對照】
使用者提到 LLM01～LLM10，指的就是下列風險項目（不是模型名稱，也不是 CVE 或 CWE 編號）：
LLM01 提示注入（Prompt Injection）
LLM02 敏感資訊洩漏（Sensitive Information Disclosure）
LLM03 供應鏈（Supply Chain）
LLM04 資料及模型投毒（Data and Model Poisoning）
LLM05 不當輸出處理（Improper Output Handling）
LLM06 過度代理授權（Excessive Agency）
LLM07 系統提示洩漏（System Prompt Leakage）
LLM08 向量與嵌入弱點（Vector and Embedding Weaknesses）
LLM09 錯誤資訊（Misinformation）
LLM10 無限制消耗（Unbounded Consumption）

【內容原則】
- 回答要正確。不確定的細節就說「不確定」，不要編造數字、編號、法規或來源。
- 不要主動列出 CWE、CVE 等編號，除非使用者詢問而且你確定正確。
- 以防禦與教學為主，說明原理、風險與具體的防護做法。"""

# ==================================
# 11. Groq 雲端 AI 模型（需登入）
# ==================================

@app.post("/api/chat")
def chat_with_ai(req: ChatRequest, user=Depends(current_user)):

    api_key = os.environ.get("LLM_Guard2")

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="尚未設定 LLM_Guard2"
        )

    if not req.message.strip():
        raise HTTPException(
            status_code=400,
            detail="請輸入問題"
        )

    try:
        client = Groq(api_key=api_key)

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": req.message
                }
            ]
        )

        ai_reply = response.choices[0].message.content

        return {
            "status": "success",
            "reply": ai_reply,
            "model": MODEL_NAME
        }

    except Exception as e:
        print("Groq API Error:", str(e))

        raise HTTPException(
            status_code=502,
            detail=f"雲端模型呼叫失敗：{str(e)}"
        )
