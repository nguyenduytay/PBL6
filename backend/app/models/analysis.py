"""
Analysis Models - Database models cho lưu lịch sử phân tích
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from pydantic import BaseModel, Field


class AnalysisBase(BaseModel):
    """Base model cho Analysis"""
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_size: Optional[int] = None
    analysis_time: float = 0.0
    malware_detected: bool = False
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: List[str] = Field(default_factory=list)
    capabilities: List[Dict[str, Any]] = Field(default_factory=list)


class AnalysisCreate(AnalysisBase):
    """Model để tạo analysis mới"""
    pass


class AnalysisResponse(AnalysisBase):
    """Model response cho API"""
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


@dataclass
class Analysis:
    """Analysis database model"""
    id: Optional[int] = None
    filename: str = ""
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_size: Optional[int] = None
    upload_time: Optional[datetime] = None
    analysis_time: float = 0.0
    malware_detected: bool = False
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: List[str] = field(default_factory=list)
    capabilities: List[Dict[str, Any]] = field(default_factory=list)
    created_at: Optional[datetime] = None


@dataclass
class YaraMatch:
    """YARA match database model"""
    id: Optional[int] = None
    analysis_id: Optional[int] = None
    rule_name: str = ""
    tags: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[datetime] = None

