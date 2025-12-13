"""
Constants Module - Application-wide constants
Module này chứa các constants dùng chung cho toàn bộ ứng dụng
"""

# File size limits
MAX_UPLOAD_SIZE_GB = 2
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_GB * 1024 * 1024 * 1024

# Pagination defaults
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100
DEFAULT_OFFSET = 0

# Analysis status
class AnalysisStatus:
    """Analysis status constants"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

# Malware detection results
class DetectionResult:
    """Malware detection result constants"""
    CLEAN = "clean"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"

# Supported file extensions
SUPPORTED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".drv",  # Windows executables
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",  # Office documents
    ".zip", ".rar", ".7z", ".tar", ".gz",  # Archives
    ".js", ".vbs", ".ps1", ".bat", ".cmd",  # Scripts
    ".jar", ".class",  # Java
    ".apk",  # Android
]

# YARA match severity levels
class YaraSeverity:
    """YARA match severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

