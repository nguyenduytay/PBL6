"""
Analysis Schemas - Validation cho analysis API
Pydantic models để validate request/response của các endpoint quản lý analyses
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
import html


class AnalysisBase(BaseModel):
    """
    Base schema cho Analysis - Chứa các fields chung
    
    Attributes:
        filename: Tên file
        sha256: SHA256 hash
        md5: MD5 hash
        file_size: Kích thước file (bytes)
        analysis_time: Thời gian phân tích (seconds)
        malware_detected: Có phát hiện malware không
        yara_matches: Danh sách YARA matches
        pe_info: PE file information
        suspicious_strings: Danh sách suspicious strings
        capabilities: File capabilities
    """
    filename: str = Field(..., min_length=1, max_length=255, description="Tên file")
    sha256: Optional[str] = Field(None, max_length=64, description="SHA256 hash")
    md5: Optional[str] = Field(None, max_length=32, description="MD5 hash")
    file_size: Optional[int] = Field(None, ge=0, description="Kích thước file (bytes)")
    analysis_time: float = Field(default=0.0, ge=0, description="Thời gian phân tích (seconds)")
    malware_detected: bool = Field(default=False, description="Có phát hiện malware không")
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list, description="YARA rule matches")
    pe_info: Optional[Dict[str, Any]] = Field(None, description="PE file information")
    suspicious_strings: List[str] = Field(default_factory=list, description="Suspicious strings")
    capabilities: List[Dict[str, Any]] = Field(default_factory=list, description="File capabilities")
    
    @field_validator('filename')
    @classmethod
    def sanitize_filename(cls, v: str) -> str:
        """
        Sanitize filename để prevent XSS attacks
        
        Args:
            v: Filename string
            
        Returns:
            str: Sanitized filename
        """
        # Escape HTML để tránh XSS, loại bỏ khoảng trắng thừa
        return html.escape(v.strip())


class AnalysisCreate(AnalysisBase):
    """
    Schema để tạo analysis mới - Dùng trong POST /api/analyses
    
    Example:
        >>> data = AnalysisCreate(
        ...     filename="test.exe",
        ...     sha256="abc123...",
        ...     malware_detected=True
        ... )
    """
    pass


class AnalysisUpdate(BaseModel):
    """
    Schema để update analysis - Dùng trong PUT /api/analyses/{id}
    Tất cả fields đều optional để chỉ update những field cần thiết
    """
    # Tất cả fields đều optional - chỉ update những field được gửi lên
    filename: Optional[str] = Field(None, min_length=1, max_length=255)
    malware_detected: Optional[bool] = None
    yara_matches: Optional[List[Dict[str, Any]]] = None
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: Optional[List[str]] = None
    capabilities: Optional[List[Dict[str, Any]]] = None


class AnalysisResponse(AnalysisBase):
    """
    Schema response cho API - Dùng trong GET endpoints
    
    Attributes:
        id: Analysis ID
        created_at: Thời gian tạo
        upload_time: Thời gian upload
        
    Example:
        >>> response = AnalysisResponse(
        ...     id=1,
        ...     filename="test.exe",
        ...     created_at=datetime.now()
        ... )
    """
    id: int = Field(..., description="Analysis ID")
    created_at: datetime = Field(..., description="Thời gian tạo")
    upload_time: Optional[datetime] = Field(None, description="Thời gian upload")
    
    class Config:
        """Pydantic config - Cấu hình serialization"""
        from_attributes = True  # Cho phép tạo từ ORM objects
        populate_by_name = True  # Cho phép dùng alias hoặc tên field
        json_encoders = {
            datetime: lambda v: v.isoformat()  # Chuyển datetime sang ISO format
        }


class AnalysisListItemResponse(BaseModel):
    """
    Schema cho list item - Dùng trong GET /api/analyses (list endpoint)
    Chỉ chứa các fields cần thiết để hiển thị trong list, không có full details
    """
    id: int
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_size: Optional[int] = None
    analysis_time: Optional[float] = None
    malware_detected: bool
    created_at: datetime
    upload_time: Optional[datetime] = None
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        from_attributes = True
