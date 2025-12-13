"""
Get Analyses List Use Case - Use case để lấy danh sách analyses với pagination
"""
from typing import List
from app.domain.analyses.models import Analysis
from app.domain.analyses.services import AnalysisService
from app.core.logging import get_logger

logger = get_logger(__name__)


class GetAnalysesListUseCase:
    """
    Get Analyses List Use Case - Use case để lấy danh sách analyses
    
    Use case này:
    1. Validate pagination parameters
    2. Call domain service để lấy analyses
    3. Return paginated result với total count
    """
    
    def __init__(self, analysis_service: AnalysisService):
        """
        Initialize GetAnalysesListUseCase với analysis service
        
        Args:
            analysis_service: AnalysisService instance (injected)
        """
        self.analysis_service = analysis_service
    
    async def execute(self, limit: int = 100, offset: int = 0) -> dict:
        """
        Execute use case - Lấy danh sách analyses với pagination
        
        Args:
            limit: Số lượng kết quả tối đa
            offset: Vị trí bắt đầu
            
        Returns:
            dict: Dictionary chứa items (List[Analysis]), total (int), limit, offset
            
        Example:
            >>> result = await use_case.execute(limit=20, offset=0)
            >>> print(f"Total: {result['total']}, Items: {len(result['items'])}")
        """
        # Get analyses từ domain service
        analyses = await self.analysis_service.get_analyses_list(limit=limit, offset=offset)
        
        # Get total count
        total = await self.analysis_service.repository.count_all()
        
        logger.info(f"Retrieved {len(analyses)} analyses (total: {total})")
        
        return {
            "items": analyses,
            "total": total,
            "limit": limit,
            "offset": offset
        }

