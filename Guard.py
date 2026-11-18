from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from groq import Groq
from sqlalchemy import create_engine, text
import os

app = FastAPI(title="LLM GUARD API")

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
        db_url = db_url.replace(
            "postgres://",
            "postgresql+psycopg://",
            1
        )

    elif db_url.startswith("postgresql://"):
        db_url = db_url.replace(
            "postgresql://",
            "postgresql+psycopg://",
            1
        )

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

# ==================================
# 3. 使用者問題格式
# ==================================

class ChatRequest(BaseModel):
    message: str

# ==================================
# 4. API 健康檢查
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
# 5. Groq 雲端 AI 模型
# ==================================

@app.post("/api/chat")
def chat_with_ai(req: ChatRequest):

    api_key = os.environ.get("GROQ_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="尚未設定 GROQ_API_KEY"
        )

    if not req.message.strip():
        raise HTTPException(
            status_code=400,
            detail="請輸入問題"
        )

    try:
        client = Groq(api_key=api_key)

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {
                    "role": "system",
                    "content": """
                    你是一位專精於大型語言模型、
                    AI 資安與 OWASP 防禦機制的專業助理。

                    請一律使用繁體中文回答，
                    回答應清楚、專業且有條理。
                    """
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
            "model": "openai/gpt-oss-20b"
        }

    except Exception as e:
        print("Groq API Error:", str(e))

        raise HTTPException(
            status_code=502,
            detail=f"雲端模型呼叫失敗：{str(e)}"
        )
