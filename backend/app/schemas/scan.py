"""
Scan Schemas - Validation cho scan API
Pydantic models để validate request/response của các endpoint quét file
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FileAnalysisResult(BaseModel):
    """Kết quả phân tích một file - Dùng cho từng kết quả riêng lẻ"""
    type: str = Field(..., description="Loại kết quả: hash, yara, clean, yara_error")
    sha256: Optional[str] = None
    uri: Optional[str] = None
    malwareType: Optional[str] = None
    firstSeen: Optional[str] = None
    infoUrl: Optional[str] = None  # Link tham khảo (ví dụ: bazaar.abuse.ch)
    file: Optional[str] = None
    matches: Optional[str] = None  # YARA matches string
    rule_count: Optional[int] = None  # Số lượng YARA rules khớp
    message: Optional[str] = None

class AnalysisResult(BaseModel):
    """Kết quả phân tích tổng hợp - Dùng cho batch scan"""
    filename: str
    results: List[FileAnalysisResult] = Field(default_factory=list)  # Danh sách kết quả
    elapsed: float = 0.0  # Thời gian phân tích (giây)
    analysis_type: str = "single_file"  # Loại phân tích: single_file hoặc folder

class ScanResult(BaseModel):
    """API response schema cho /api/scan - Kết quả scan file"""
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)  # YARA matches chi tiết
    pe_info: Optional[Dict[str, Any]] = None  # Thông tin PE file
    suspicious_strings: List[str] = Field(default_factory=list)  # Strings đáng ngờ
    capabilities: List[Dict[str, Any]] = Field(default_factory=list)  # Khả năng của file
    malware_detected: bool = False  # Có phát hiện malware không
    analysis_time: float = 0.0  # Thời gian phân tích (giây)
    results: List[Dict[str, Any]] = Field(default_factory=list, description="Chi tiết các phát hiện (Hash, Yara, EMBER)")

