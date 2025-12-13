"""
Main application entry point
FastAPI application với kiến trúc chuẩn
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).parent.parent.parent

from app.core.config import settings
from app.api.v1 import api_router
from app.database.connection import init_db

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL
)

# Cấu hình CORS để React frontend có thể gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React dev server
        "http://localhost:5173",  # Vite dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Hiển thị thông tin truy cập khi server khởi động"""
    # Initialize database
    try:
        await init_db()
        print("[OK] Database initialized")
    except Exception as e:
        print(f"[WARN] Database initialization failed: {e}")
        print("[INFO] Analysis history will not be saved")
    
    # Load YARA rules
    settings.load_yara_rules()
    
    # Initialize Static Analyzer
    settings.init_static_analyzer()
    
    # Print startup info
    print("\n" + "="*60)
    print("[INFO] Malware Detector API da khoi dong!")
    print("="*60)
    print("\n[INFO] Backend API da khoi dong!")
    print("   API Base URL:   http://localhost:5000/api")
    print("   API Docs:       http://localhost:5000/api/docs")
    print("   ReDoc:          http://localhost:5000/api/redoc")
    print("   Health Check:   http://localhost:5000/api/health")
    print("\n[INFO] CORS enabled for React frontend (localhost:3000, localhost:5173)")
    print("="*60 + "\n")

# Include API routes only (không cần web routes nữa vì dùng React)
app.include_router(api_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    import uvicorn
    # Chạy server - host="0.0.0.0" cho phép truy cập từ localhost và LAN
    # Nhưng để truy cập từ browser, phải dùng http://localhost:5000 (KHÔNG dùng http://0.0.0.0:5000)
    uvicorn.run(
        "app.main:app",  # Use string để reload hoạt động
        host=settings.HOST,
        port=settings.PORT,
        reload=False,  # Set to False khi chạy trực tiếp
        log_level="info"
    )
