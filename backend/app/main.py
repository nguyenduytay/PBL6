"""
Main Application Entry Point - FastAPI application
Điểm khởi đầu của ứng dụng, khởi tạo FastAPI app và các middleware

Kiến trúc:
- Core: Configuration, Security, Database, Logging
- Services: Business logic (phân tích malware)
- ML: Machine Learning models (EMBER)
- Utils: Tiện ích (file handling, validation)
- API: HTTP endpoints
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables từ .env file
load_dotenv()

# Import core modules
from app.core.config import settings
from app.core.logging import setup_logging, get_logger

# Setup logging
logger = setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)

# Import database initialization
from app.core.database import init_database

# Initialize FastAPI app với metadata
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Cấu hình CORS - Cho phép React frontend gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted Host Middleware - Chỉ accept requests từ trusted hosts
# TODO: Cấu hình allowed_hosts từ environment trong production
# app.add_middleware(
#     TrustedHostMiddleware,
#     allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"]
# )


@app.on_event("startup")
async def startup_event():
    """
    Startup Event - Khởi tạo application khi server start
    
    Thực hiện:
    1. Initialize database
    2. Load YARA rules
    3. Initialize Static Analyzer
    4. Log startup info
    """
    logger.info("="*60)
    logger.info(f"{settings.APP_NAME} v{settings.APP_VERSION} - Starting up...")
    logger.info("="*60)
    
    # Initialize database
    try:
        success = await init_database()
        if success:
            logger.info("Database initialized successfully")
        else:
            logger.warning("Database initialization failed - Analysis history will not be saved")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    # Load YARA rules
    try:
        rules = settings.load_yara_rules()
        if rules:
            rule_count = len(list(rules))
            logger.info(f"YARA rules loaded: {rule_count} rules")
        else:
            logger.warning("YARA rules not loaded")
    except Exception as e:
        logger.error(f"Error loading YARA rules: {e}")
    
    # Initialize Static Analyzer
    try:
        analyzer = settings.init_static_analyzer()
        if analyzer:
            logger.info("Static Analyzer initialized successfully")
        else:
            logger.warning("Static Analyzer not initialized")
    except Exception as e:
        logger.error(f"Error initializing Static Analyzer: {e}")
    
    # Print startup info
    logger.info("="*60)
    logger.info("Backend API started successfully!")
    logger.info(f"   API Base URL:   http://{settings.HOST}:{settings.PORT}{settings.API_V1_STR}")
    logger.info(f"   API Docs:       http://{settings.HOST}:{settings.PORT}{settings.DOCS_URL}")
    logger.info(f"   ReDoc:          http://{settings.HOST}:{settings.PORT}{settings.REDOC_URL}")
    logger.info(f"   Health Check:   http://{settings.HOST}:{settings.PORT}{settings.API_V1_STR}/health")
    logger.info(f"   CORS Origins:   {', '.join(settings.CORS_ORIGINS)}")
    logger.info("="*60)


@app.on_event("shutdown")
async def shutdown_event():
    """
    Shutdown Event - Cleanup khi server shutdown
    
    Thực hiện:
    1. Close database connections
    2. Cleanup resources
    """
    logger.info("Shutting down application...")
    # TODO: Close database pool, cleanup resources
    logger.info("Application shut down successfully")


# Include API routes
# Import API routes - có thể mất thời gian do load EMBER model
try:
    logger.info("Importing API routes...")
    from app.api.v1 import api_router
    logger.info("API routes imported successfully")
    app.include_router(api_router, prefix=settings.API_V1_STR)
    logger.info("API routes registered successfully")
except ImportError as e:
    logger.error(f"Failed to import API router: {e}")
    logger.warning("API routes not loaded. Check API module imports.")


if __name__ == "__main__":
    """
    Main entry point - Chạy application với uvicorn
    
    Usage:
        python -m app.main
        hoặc
        uvicorn app.main:app --host 0.0.0.0 --port 5000
    """
    import uvicorn
    
    uvicorn.run(
        "app.main:app",  # Use string để reload hoạt động
        host=settings.HOST,
        port=settings.PORT,
        reload=False,  # Set to True trong development
        log_level=settings.LOG_LEVEL.lower()
    )
