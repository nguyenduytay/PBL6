"""
API v1 module
"""
from fastapi import APIRouter
from .routes import scan, health, websocket, analyses

api_router = APIRouter()

# Include API routes (prefix /api sẽ được thêm ở main.py)
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(websocket.router, prefix="/ws", tags=["websocket"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])

