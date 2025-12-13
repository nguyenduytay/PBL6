"""
Logging Module - Centralized logging và monitoring
Module này cung cấp logging structured và audit logging cho ứng dụng
"""
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
import json

# Configure logging format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Create logs directory
LOGS_DIR = Path(__file__).parent.parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logging configuration cho ứng dụng
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. Nếu None, chỉ log ra console
        
    Returns:
        logging.Logger: Configured logger instance
        
    Example:
        >>> logger = setup_logging("INFO", "app.log")
        >>> logger.info("Application started")
    """
    logger = logging.getLogger("malware_detector")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (nếu có)
    if log_file:
        file_path = LOGS_DIR / log_file
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "malware_detector") -> logging.Logger:
    """
    Get logger instance cho module cụ thể
    
    Args:
        name: Logger name (thường là module name)
        
    Returns:
        logging.Logger: Logger instance
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing file")
    """
    return logging.getLogger(name)


async def log_audit(
    action: str,
    user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None
) -> None:
    """
    Log audit event - Ghi lại các hành động quan trọng của user
    
    Args:
        action: Tên hành động (ví dụ: "user_login", "file_uploaded", "analysis_created")
        user_id: ID của user thực hiện hành động (nếu có)
        details: Dictionary chứa thông tin chi tiết về hành động
        logger: Optional logger instance. Nếu None, dùng default logger
        
    Example:
        >>> await log_audit(
        ...     action="file_uploaded",
        ...     user_id=1,
        ...     details={"filename": "test.exe", "file_size": 1024}
        ... )
    """
    if logger is None:
        logger = get_logger("audit")
    
    audit_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user_id": user_id,
        "details": details or {}
    }
    
    logger.info(f"AUDIT: {json.dumps(audit_data)}")


def log_request(request_id: str, method: str, path: str, logger: Optional[logging.Logger] = None) -> None:
    """
    Log HTTP request - Ghi lại thông tin request để tracing
    
    Args:
        request_id: Unique request ID để trace request qua các services
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        path: Request path
        logger: Optional logger instance
        
    Example:
        >>> log_request("req-123", "POST", "/api/scan")
    """
    if logger is None:
        logger = get_logger("request")
    
    logger.info(f"REQUEST [{request_id}]: {method} {path}")


def log_error(
    error: Exception,
    context: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None
) -> None:
    """
    Log error với context - Ghi lại lỗi kèm thông tin context
    
    Args:
        error: Exception object
        context: Dictionary chứa thông tin context (user_id, request_id, etc.)
        logger: Optional logger instance
        
    Example:
        >>> try:
        ...     process_file()
        ... except Exception as e:
        ...     log_error(e, {"file": "test.exe", "user_id": 1})
    """
    if logger is None:
        logger = get_logger("error")
    
    error_data = {
        "error_type": type(error).__name__,
        "error_message": str(error),
        "context": context or {}
    }
    
    logger.error(f"ERROR: {json.dumps(error_data)}", exc_info=True)


# Initialize default logger
default_logger = setup_logging("INFO")

