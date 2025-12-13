"""
Repository Interfaces - Abstract repository interfaces cho Analysis domain
Đây là abstractions, implementations sẽ ở infrastructure layer
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from app.domain.analyses.models import Analysis


class IAnalysisRepository(ABC):
    """
    Analysis Repository Interface - Abstract interface cho analysis repository
    
    Interface này định nghĩa các methods cần thiết để thao tác với analysis data
    Implementation sẽ ở infrastructure layer
    """
    
    @abstractmethod
    async def create(self, analysis: Analysis) -> Optional[int]:
        """
        Tạo analysis mới trong database
        
        Args:
            analysis: Analysis domain model
            
        Returns:
            Optional[int]: ID của analysis vừa tạo, None nếu lỗi
            
        Example:
            >>> analysis = Analysis(filename="test.exe")
            >>> analysis_id = await repo.create(analysis)
        """
        pass
    
    @abstractmethod
    async def get_by_id(self, analysis_id: int) -> Optional[Analysis]:
        """
        Lấy analysis theo ID
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            Optional[Analysis]: Analysis domain model hoặc None nếu không tìm thấy
            
        Example:
            >>> analysis = await repo.get_by_id(1)
            >>> if analysis:
            ...     print(analysis.filename)
        """
        pass
    
    @abstractmethod
    async def get_all(self, limit: int = 100, offset: int = 0) -> List[Analysis]:
        """
        Lấy danh sách analyses với pagination
        
        Args:
            limit: Số lượng kết quả tối đa
            offset: Vị trí bắt đầu
            
        Returns:
            List[Analysis]: Danh sách analyses
            
        Example:
            >>> analyses = await repo.get_all(limit=20, offset=0)
            >>> for analysis in analyses:
            ...     print(analysis.filename)
        """
        pass
    
    @abstractmethod
    async def get_by_sha256(self, sha256: str) -> Optional[Analysis]:
        """
        Lấy analysis theo SHA256 hash
        
        Args:
            sha256: SHA256 hash string
            
        Returns:
            Optional[Analysis]: Analysis domain model hoặc None nếu không tìm thấy
            
        Example:
            >>> analysis = await repo.get_by_sha256("abc123...")
        """
        pass
    
    @abstractmethod
    async def search(self, query: str, limit: int = 50, offset: int = 0) -> List[Analysis]:
        """
        Tìm kiếm analyses theo filename, SHA256, hoặc MD5
        
        Args:
            query: Từ khóa tìm kiếm
            limit: Số lượng kết quả tối đa
            offset: Vị trí bắt đầu
            
        Returns:
            List[Analysis]: Danh sách analyses khớp với query
            
        Example:
            >>> results = await repo.search("test.exe", limit=10)
        """
        pass
    
    @abstractmethod
    async def count_all(self) -> int:
        """
        Đếm tổng số analyses trong database
        
        Returns:
            int: Tổng số analyses
            
        Example:
            >>> total = await repo.count_all()
            >>> print(f"Total analyses: {total}")
        """
        pass
    
    @abstractmethod
    async def count_search(self, query: str) -> int:
        """
        Đếm tổng số kết quả search
        
        Args:
            query: Từ khóa tìm kiếm
            
        Returns:
            int: Tổng số kết quả
            
        Example:
            >>> count = await repo.count_search("test")
        """
        pass
    
    @abstractmethod
    async def delete(self, analysis_id: int) -> bool:
        """
        Xóa analysis theo ID
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            bool: True nếu xóa thành công, False nếu không
            
        Example:
            >>> success = await repo.delete(1)
        """
        pass
    
    @abstractmethod
    async def update(self, analysis_id: int, analysis_data: Dict[str, Any]) -> bool:
        """
        Update analysis
        
        Args:
            analysis_id: Analysis ID
            analysis_data: Dictionary chứa data cần update
            
        Returns:
            bool: True nếu update thành công, False nếu không
            
        Example:
            >>> success = await repo.update(1, {"malware_detected": True})
        """
        pass

