"""
Analysis Models - Data models
Dataclasses cho Analysis và YaraMatch, dùng để lưu trữ và xử lý dữ liệu phân tích
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class Analysis:
    """
    Analysis Model - Entity đại diện cho một lần phân tích malware
    
    Attributes:
        id: Unique identifier của analysis
        filename: Tên file được phân tích
        sha256: SHA256 hash của file
        md5: MD5 hash của file
        file_size: Kích thước file (bytes)
        upload_time: Thời gian upload file
        analysis_time: Thời gian phân tích (seconds)
        malware_detected: Có phát hiện malware không
        yara_matches: Danh sách YARA rule matches
        pe_info: PE file information (nếu là PE file)
        suspicious_strings: Danh sách suspicious strings
        capabilities: File capabilities
        created_at: Thời gian tạo record
        
    Example:
        >>> analysis = Analysis(
        ...     filename="test.exe",
        ...     sha256="abc123...",
        ...     malware_detected=True
        ... )
    """
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
    
    def is_malware(self) -> bool:
        """
        Kiểm tra xem file có phải malware không
        
        Returns:
            bool: True nếu malware_detected = True hoặc có YARA matches
            
        Example:
            >>> if analysis.is_malware():
            ...     print("Malware detected!")
        """
        # File là malware nếu được đánh dấu hoặc có YARA matches
        return self.malware_detected or len(self.yara_matches) > 0
    
    def get_severity(self) -> str:
        """
        Tính severity level của analysis dựa trên kết quả
        
        Returns:
            str: Severity level ("critical", "high", "medium", "low", "clean")
            
        Example:
            >>> severity = analysis.get_severity()
            >>> if severity == "critical":
            ...     send_alert()
        """
        # File sạch nếu không phát hiện malware
        if not self.is_malware():
            return "clean"
        
        # Phân loại severity dựa trên số lượng YARA matches
        # Nhiều matches = mức độ nghi ngờ cao hơn
        if len(self.yara_matches) >= 5:
            return "critical"  # Rất nghiêm trọng
        elif len(self.yara_matches) >= 3:
            return "high"  # Cao
        elif len(self.yara_matches) >= 1:
            return "medium"  # Trung bình
        else:
            return "low"  # Thấp


@dataclass
class YaraMatch:
    """
    YARA Match Model - Entity đại diện cho một YARA rule match
    
    Attributes:
        id: Unique identifier
        analysis_id: ID của analysis liên quan
        rule_name: Tên YARA rule
        tags: Tags của rule
        description: Mô tả của rule
        created_at: Thời gian tạo
        
    Example:
        >>> match = YaraMatch(
        ...     rule_name="Trojan.Generic",
        ...     tags="trojan,malware",
        ...     description="Generic trojan detection"
        ... )
    """
    id: Optional[int] = None
    analysis_id: Optional[int] = None
    rule_name: str = ""
    tags: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[datetime] = None
