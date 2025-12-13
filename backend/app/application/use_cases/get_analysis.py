"""
Get Analysis Use Case - Use case để lấy analysis detail
Use case này orchestrate domain services để lấy thông tin analysis
"""
from typing import Optional
from app.domain.analyses.models import Analysis
from app.domain.analyses.services import AnalysisService
from app.shared.exceptions import NotFoundException
from app.core.logging import get_logger, log_audit

logger = get_logger(__name__)


class GetAnalysisUseCase:
    """
    Get Analysis Use Case - Use case để lấy analysis detail theo ID
    
    Use case này:
    1. Validate input
    2. Call domain service để lấy analysis
    3. Log audit event
    4. Return result
    """
    
    def __init__(self, analysis_service: AnalysisService):
        """
        Initialize GetAnalysisUseCase với analysis service
        
        Args:
            analysis_service: AnalysisService instance (injected)
            
        Example:
            >>> service = AnalysisService(repo)
            >>> use_case = GetAnalysisUseCase(service)
        """
        self.analysis_service = analysis_service
    
    async def execute(self, analysis_id: int, user_id: Optional[int] = None) -> Analysis:
        """
        Execute use case - Lấy analysis detail
        
        Args:
            analysis_id: Analysis ID cần lấy
            user_id: Optional user ID để log audit
            
        Returns:
            Analysis: Analysis domain model
            
        Raises:
            NotFoundException: Nếu không tìm thấy analysis
            
        Example:
            >>> analysis = await use_case.execute(1, user_id=1)
            >>> print(analysis.filename)
        """
        # Log audit event
        await log_audit(
            action="get_analysis",
            user_id=user_id,
            details={"analysis_id": analysis_id},
            logger=logger
        )
        
        # Call domain service
        analysis = await self.analysis_service.get_analysis_by_id(analysis_id)
        
        logger.info(f"Analysis {analysis_id} retrieved successfully")
        
        return analysis

