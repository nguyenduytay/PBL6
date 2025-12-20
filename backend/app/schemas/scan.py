"""
Scan Schemas - Validation cho scan API
Pydantic models để validate request/response của các endpoint quét file
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FileAnalysisResult(BaseModel):
    """Kết quả phân tích một file"""
    type: str = Field(..., description="Loại kết quả: hash, yara, clean, yara_error")
    sha256: Optional[str] = None
    uri: Optional[str] = None
    malwareType: Optional[str] = None
    firstSeen: Optional[str] = None
    infoUrl: Optional[str] = None
    file: Optional[str] = None
    matches: Optional[str] = None
    rule_count: Optional[int] = None
    message: Optional[str] = None

class AnalysisResult(BaseModel):
    """Kết quả phân tích tổng hợp"""
    filename: str
    results: List[FileAnalysisResult] = Field(default_factory=list)
    elapsed: float = 0.0
    analysis_type: str = "single_file"  # single_file hoặc folder

class ScanResult(BaseModel):
    """API response schema cho /api/scan"""
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: List[str] = Field(default_factory=list)
    capabilities: List[Dict[str, Any]] = Field(default_factory=list)
    malware_detected: bool = False
    analysis_time: float = 0.0
    results: List[Dict[str, Any]] = Field(default_factory=list, description="Chi tiết các phát hiện (Hash, Yara, EMBER)")

