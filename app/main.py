"""
Main application entry point
FastAPI application với kiến trúc chuẩn
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).parent.parent.parent

from app.core.config import settings
from app.api.v1 import api_router
from app.api.v1.routes import web
from app.database.connection import init_db

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL
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
    print("\n[INFO] Truy cap ung dung:")
    print("   Web UI:        http://localhost:5000")
    print("   API Docs:       http://localhost:5000/api/docs")
    print("   ReDoc:          http://localhost:5000/api/redoc")
    print("   Health Check:   http://localhost:5000/api/health")
    print("\n[WARN] LUU Y: Dung http://localhost:5000 (KHONG dung http://0.0.0.0:5000)")
    print("="*60 + "\n")

# Mount static files (CSS, JS, images)
# Cho phép truy cập các file tĩnh qua URL /static/*
static_dir = settings.STATIC_DIR

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    print(f"[OK] Static files mounted at: /static (from {static_dir})")
else:
    print(f"[WARN] Static directory not found: {static_dir}")

# Include API routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Include web routes (HTML pages)
app.include_router(web.router)

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

