"""
Analyses Endpoints - API endpoints cho Analysis operations
Endpoints này handle HTTP requests/responses và delegate logic cho use cases
"""
from typing import List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.domain.analyses.schemas import (
    AnalysisResponse,
    AnalysisListItemResponse,
    AnalysisCreate,
    AnalysisUpdate
)
from app.domain.analyses.services import AnalysisService
from app.domain.analyses.repositories import IAnalysisRepository
from app.infrastructure.repositories.analysis_repository import AnalysisRepository
from app.application.use_cases.get_analysis import GetAnalysisUseCase
from app.application.use_cases.get_analyses_list import GetAnalysesListUseCase
from app.core.dependencies import get_request_id
from app.core.logging import get_logger, log_request, log_error
from app.shared.exceptions import NotFoundException, BusinessException, InternalServerException

logger = get_logger(__name__)

router = APIRouter(prefix="/analyses", tags=["analyses"])


def get_analysis_repository() -> IAnalysisRepository:
    """
    Dependency: Get AnalysisRepository instance
    
    Returns:
        IAnalysisRepository: Repository instance
        
    Usage:
        @router.get("/")
        async def endpoint(repo = Depends(get_analysis_repository)):
            ...
    """
    return AnalysisRepository()


def get_analysis_service(
    repo: IAnalysisRepository = Depends(get_analysis_repository)
) -> AnalysisService:
    """
    Dependency: Get AnalysisService instance với repository injected
    
    Args:
        repo: AnalysisRepository instance (injected)
        
    Returns:
        AnalysisService: Service instance
        
    Usage:
        @router.get("/")
        async def endpoint(service = Depends(get_analysis_service)):
            ...
    """
    return AnalysisService(repo)


def get_analysis_use_case(
    service: AnalysisService = Depends(get_analysis_service)
) -> GetAnalysisUseCase:
    """
    Dependency: Get GetAnalysisUseCase instance với service injected
    
    Args:
        service: AnalysisService instance (injected)
        
    Returns:
        GetAnalysisUseCase: Use case instance
    """
    return GetAnalysisUseCase(service)


def get_analyses_list_use_case(
    service: AnalysisService = Depends(get_analysis_service)
) -> GetAnalysesListUseCase:
    """
    Dependency: Get GetAnalysesListUseCase instance
    
    Args:
        service: AnalysisService instance (injected)
        
    Returns:
        GetAnalysesListUseCase: Use case instance
    """
    return GetAnalysesListUseCase(service)


@router.get("", response_model=dict)
async def get_analyses(
    limit: int = Query(100, ge=1, le=1000, description="Số lượng kết quả (1-1000)"),
    offset: int = Query(0, ge=0, description="Vị trí bắt đầu"),
    request_id: str = Depends(get_request_id),
    use_case: GetAnalysesListUseCase = Depends(get_analyses_list_use_case)
):
    """
    Lấy danh sách analyses với pagination
    
    Args:
        limit: Số lượng kết quả (1-1000)
        offset: Vị trí bắt đầu
        request_id: Request ID để tracing
        use_case: GetAnalysesListUseCase instance (injected)
        
    Returns:
        dict: Dictionary chứa items, total, limit, offset
        
    Raises:
        HTTPException: Nếu có lỗi xảy ra
        
    Example:
        GET /api/analyses?limit=20&offset=0
    """
    log_request(request_id, "GET", f"/analyses?limit={limit}&offset={offset}", logger)
    
    try:
        result = await use_case.execute(limit=limit, offset=offset)
        
        # Convert domain models sang response schemas
        items = [
            AnalysisListItemResponse(
                id=a.id,
                filename=a.filename,
                sha256=a.sha256,
                md5=a.md5,
                file_size=a.file_size,
                analysis_time=a.analysis_time,
                malware_detected=a.malware_detected,
                created_at=a.created_at,
                upload_time=a.upload_time,
                yara_matches=a.yara_matches
            )
            for a in result["items"]
        ]
        
        return {
            "items": items,
            "total": result["total"],
            "limit": result["limit"],
            "offset": result["offset"]
        }
        
    except BusinessException as e:
        logger.warning(f"Business error: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        log_error(e, {"request_id": request_id, "endpoint": "get_analyses"}, logger)
        raise InternalServerException("Error fetching analyses")


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: int,
    request_id: str = Depends(get_request_id),
    use_case: GetAnalysisUseCase = Depends(get_analysis_use_case)
):
    """
    Lấy analysis detail theo ID
    
    Args:
        analysis_id: Analysis ID
        request_id: Request ID để tracing
        use_case: GetAnalysisUseCase instance (injected)
        
    Returns:
        AnalysisResponse: Analysis detail
        
    Raises:
        HTTPException: Nếu không tìm thấy hoặc có lỗi
        
    Example:
        GET /api/analyses/1
    """
    log_request(request_id, "GET", f"/analyses/{analysis_id}", logger)
    
    try:
        analysis = await use_case.execute(analysis_id)
        
        # Convert domain model sang response schema
        return AnalysisResponse(
            id=analysis.id,
            filename=analysis.filename,
            sha256=analysis.sha256,
            md5=analysis.md5,
            file_size=analysis.file_size,
            analysis_time=analysis.analysis_time,
            malware_detected=analysis.malware_detected,
            yara_matches=analysis.yara_matches,
            pe_info=analysis.pe_info,
            suspicious_strings=analysis.suspicious_strings,
            capabilities=analysis.capabilities,
            created_at=analysis.created_at,
            upload_time=analysis.upload_time
        )
        
    except NotFoundException as e:
        logger.warning(f"Analysis {analysis_id} not found")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        log_error(e, {"request_id": request_id, "analysis_id": analysis_id}, logger)
        raise InternalServerException("Error fetching analysis")


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(
    analysis_id: int,
    request_id: str = Depends(get_request_id),
    service: AnalysisService = Depends(get_analysis_service)
):
    """
    Xóa analysis theo ID
    
    Args:
        analysis_id: Analysis ID
        request_id: Request ID để tracing
        service: AnalysisService instance (injected)
        
    Returns:
        None (204 No Content)
        
    Raises:
        HTTPException: Nếu không tìm thấy hoặc có lỗi
        
    Example:
        DELETE /api/analyses/1
    """
    log_request(request_id, "DELETE", f"/analyses/{analysis_id}", logger)
    
    try:
        await service.delete_analysis(analysis_id)
        logger.info(f"Analysis {analysis_id} deleted successfully")
        return None
        
    except NotFoundException as e:
        logger.warning(f"Analysis {analysis_id} not found for deletion")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except BusinessException as e:
        logger.warning(f"Business error: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        log_error(e, {"request_id": request_id, "analysis_id": analysis_id}, logger)
        raise InternalServerException("Error deleting analysis")

