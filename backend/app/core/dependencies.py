"""
Dependencies Module - Dependency Injection
Cung cấp các dependency functions (YARA rules, static analyzer, request ID) cho FastAPI
"""
from fastapi import Depends, Request
from typing import Optional
import yara

# Dependencies cho các services sẽ được thêm khi cần


def get_yara_rules() -> Optional[yara.Rules]:
    """
    Dependency: Get YARA rules instance
    
    Returns:
        Optional[yara.Rules]: YARA rules instance hoặc None nếu chưa load
        
    Usage:
        @router.post("/scan")
        async def scan_file(yara_rules: yara.Rules = Depends(get_yara_rules)):
            ...
    """
    from app.core.config import settings
    return settings.get_yara_rules()


def get_static_analyzer():
    """
    Dependency: Get Static Analyzer instance
    
    Returns:
        Static Analyzer instance hoặc None nếu chưa init
        
    Usage:
        @router.post("/scan")
        async def scan_file(analyzer = Depends(get_static_analyzer)):
            ...
    """
    from app.core.config import settings
    return settings.get_static_analyzer()


def get_request_id(request: Request) -> str:
    """
    Dependency: Get request ID từ header hoặc generate mới
    
    Request ID dùng để trace request qua các services và logs
    
    Args:
        request: FastAPI Request object
        
    Returns:
        str: Request ID
        
    Usage:
        @router.get("/endpoint")
        async def endpoint(request_id: str = Depends(get_request_id)):
            logger.info(f"Processing request {request_id}")
    """
    # Kiểm tra request ID trong header
    request_id = request.headers.get("X-Request-ID")
    
    if not request_id:
        # Tạo request ID mới nếu chưa có
        import uuid
        request_id = str(uuid.uuid4())
    
    return request_id


# Các dependencies khác sẽ được thêm khi cần

