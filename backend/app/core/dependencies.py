"""
Dependencies Module - Dependency Injection cho FastAPI
Module này cung cấp các dependency functions để inject vào FastAPI endpoints
Sử dụng FastAPI's Depends() để quản lý dependencies và lifecycle
"""
from fastapi import Depends, Request
from typing import Optional
import yara

# Import services và repositories (sẽ được implement sau)
# from app.domain.analyses.repositories import AnalysisRepository
# from app.domain.analyses.services import AnalysisService
# from app.application.use_cases.scan_file import ScanFileUseCase


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
    # Check nếu có request ID trong header
    request_id = request.headers.get("X-Request-ID")
    
    if not request_id:
        # Generate new request ID
        import uuid
        request_id = str(uuid.uuid4())
    
    return request_id


# TODO: Implement các dependencies sau khi có domain layer
# def get_analysis_repository() -> AnalysisRepository:
#     """
#     Dependency: Get AnalysisRepository instance
#     
#     Returns:
#         AnalysisRepository: Repository instance
#     """
#     from app.infrastructure.database import get_db
#     db = get_db()
#     return AnalysisRepository(db)
# 
# 
# def get_analysis_service(
#     repo: AnalysisRepository = Depends(get_analysis_repository)
# ) -> AnalysisService:
#     """
#     Dependency: Get AnalysisService instance với repository injected
#     
#     Args:
#         repo: AnalysisRepository instance (injected)
#         
#     Returns:
#         AnalysisService: Service instance
#     """
#     return AnalysisService(repo)
# 
# 
# def get_scan_file_use_case(
#     service: AnalysisService = Depends(get_analysis_service)
# ) -> ScanFileUseCase:
#     """
#     Dependency: Get ScanFileUseCase instance với service injected
#     
#     Args:
#         service: AnalysisService instance (injected)
#         
#     Returns:
#         ScanFileUseCase: Use case instance
#     """
#     return ScanFileUseCase(service)

