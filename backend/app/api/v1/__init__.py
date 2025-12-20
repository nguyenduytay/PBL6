"""
Module API v1 - Định nghĩa các routes chính của hệ thống
"""
from fastapi import APIRouter
from .routes import scan, health, websocket, analyses, batch_scan, search, export

api_router = APIRouter()

# Include API routes (prefix /api sẽ được thêm ở main.py)
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(batch_scan.router, prefix="/scan", tags=["batch-scan"])
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(websocket.router, prefix="/ws", tags=["websocket"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
api_router.include_router(search.router, prefix="/search", tags=["search"])
api_router.include_router(export.router, prefix="/export", tags=["export"])

