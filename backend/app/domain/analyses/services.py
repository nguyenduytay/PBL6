"""
Analysis Service - Business logic services cho Analysis domain
Service này chứa business logic, không phụ thuộc vào database implementation
"""
from typing import List, Dict, Any, Optional
from app.domain.analyses.models import Analysis
from app.domain.analyses.repositories import IAnalysisRepository
from app.shared.exceptions import BusinessException, NotFoundException


class AnalysisService:
    """
    Analysis Service - Business logic service cho analysis operations
    
    Service này chứa business rules và logic, sử dụng repository để persist data
    """
    
    def __init__(self, repository: IAnalysisRepository):
        """
        Initialize AnalysisService với repository
        
        Args:
            repository: Analysis repository instance (injected)
            
        Example:
            >>> repo = AnalysisRepository()
            >>> service = AnalysisService(repo)
        """
        self.repository = repository
    
    async def create_analysis(self, analysis_data: Dict[str, Any]) -> Analysis:
        """
        Tạo analysis mới với business validation
        
        Args:
            analysis_data: Dictionary chứa analysis data
            
        Returns:
            Analysis: Analysis domain model vừa tạo
            
        Raises:
            BusinessException: Nếu vi phạm business rules
            
        Example:
            >>> analysis = await service.create_analysis({
            ...     "filename": "test.exe",
            ...     "sha256": "abc123..."
            ... })
        """
        # Business rule: Filename không được trống
        if not analysis_data.get('filename'):
            raise BusinessException("Filename is required")
        
        # Business rule: Nếu có SHA256, phải đúng format (64 chars hex)
        sha256 = analysis_data.get('sha256')
        if sha256 and (len(sha256) != 64 or not all(c in '0123456789abcdefABCDEF' for c in sha256)):
            raise BusinessException("Invalid SHA256 format")
        
        # Business rule: Nếu có MD5, phải đúng format (32 chars hex)
        md5 = analysis_data.get('md5')
        if md5 and (len(md5) != 32 or not all(c in '0123456789abcdefABCDEF' for c in md5)):
            raise BusinessException("Invalid MD5 format")
        
        # Tạo Analysis domain model
        analysis = Analysis(**analysis_data)
        
        # Lưu vào database
        analysis_id = await self.repository.create(analysis)
        if not analysis_id:
            raise BusinessException("Failed to create analysis")
        
        analysis.id = analysis_id
        
        return analysis
    
    async def get_analysis_by_id(self, analysis_id: int) -> Analysis:
        """
        Lấy analysis theo ID với validation
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            Analysis: Analysis domain model
            
        Raises:
            NotFoundException: Nếu không tìm thấy analysis
            
        Example:
            >>> analysis = await service.get_analysis_by_id(1)
        """
        if analysis_id <= 0:
            raise BusinessException("Invalid analysis ID")
        
        analysis = await self.repository.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundException(f"Analysis {analysis_id} not found")
        
        return analysis
    
    async def get_analyses_list(self, limit: int = 100, offset: int = 0) -> List[Analysis]:
        """
        Lấy danh sách analyses với pagination và validation
        
        Args:
            limit: Số lượng kết quả (1-1000)
            offset: Vị trí bắt đầu (>= 0)
            
        Returns:
            List[Analysis]: Danh sách analyses
            
        Raises:
            BusinessException: Nếu limit hoặc offset không hợp lệ
            
        Example:
            >>> analyses = await service.get_analyses_list(limit=20, offset=0)
        """
        # Business rule: Limit phải trong khoảng hợp lệ
        if limit < 1 or limit > 1000:
            raise BusinessException("Limit must be between 1 and 1000")
        
        # Business rule: Offset không được âm
        if offset < 0:
            raise BusinessException("Offset must be >= 0")
        
        return await self.repository.get_all(limit=limit, offset=offset)
    
    async def search_analyses(self, query: str, limit: int = 50, offset: int = 0) -> List[Analysis]:
        """
        Tìm kiếm analyses với validation
        
        Args:
            query: Từ khóa tìm kiếm
            limit: Số lượng kết quả
            offset: Vị trí bắt đầu
            
        Returns:
            List[Analysis]: Danh sách analyses khớp
            
        Raises:
            BusinessException: Nếu query không hợp lệ
            
        Example:
            >>> results = await service.search_analyses("test.exe")
        """
        # Business rule: Query không được trống
        if not query or not query.strip():
            raise BusinessException("Search query cannot be empty")
        
        # Business rule: Query không được quá dài
        if len(query) > 255:
            raise BusinessException("Search query too long (max 255 characters)")
        
        return await self.repository.search(query.strip(), limit=limit, offset=offset)
    
    async def delete_analysis(self, analysis_id: int) -> bool:
        """
        Xóa analysis với validation
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            bool: True nếu xóa thành công
            
        Raises:
            NotFoundException: Nếu không tìm thấy analysis
            
        Example:
            >>> success = await service.delete_analysis(1)
        """
        # Kiểm tra analysis có tồn tại không
        analysis = await self.get_analysis_by_id(analysis_id)
        
        # Xóa analysis
        success = await self.repository.delete(analysis_id)
        if not success:
            raise BusinessException(f"Failed to delete analysis {analysis_id}")
        
        return True
    
    async def update_analysis(self, analysis_id: int, update_data: Dict[str, Any]) -> Analysis:
        """
        Update analysis với validation
        
        Args:
            analysis_id: Analysis ID
            update_data: Dictionary chứa data cần update
            
        Returns:
            Analysis: Updated analysis
            
        Raises:
            NotFoundException: Nếu không tìm thấy analysis
            BusinessException: Nếu update data không hợp lệ
            
        Example:
            >>> analysis = await service.update_analysis(1, {"malware_detected": True})
        """
        # Kiểm tra analysis có tồn tại không
        analysis = await self.get_analysis_by_id(analysis_id)
        
        # Validate update data
        if 'sha256' in update_data:
            sha256 = update_data['sha256']
            if sha256 and (len(sha256) != 64 or not all(c in '0123456789abcdefABCDEF' for c in sha256)):
                raise BusinessException("Invalid SHA256 format")
        
        if 'md5' in update_data:
            md5 = update_data['md5']
            if md5 and (len(md5) != 32 or not all(c in '0123456789abcdefABCDEF' for c in md5)):
                raise BusinessException("Invalid MD5 format")
        
        # Update analysis
        success = await self.repository.update(analysis_id, update_data)
        if not success:
            raise BusinessException(f"Failed to update analysis {analysis_id}")
        
        # Lấy lại analysis đã update
        return await self.get_analysis_by_id(analysis_id)

