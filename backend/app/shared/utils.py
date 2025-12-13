"""
Utils Module - Utility functions dùng chung
Module này chứa các utility functions helper dùng chung cho toàn bộ ứng dụng
"""
import hashlib
import os
from pathlib import Path
from typing import Optional
import uuid
from datetime import datetime


def calculate_sha256(filepath: str) -> str:
    """
    Calculate SHA256 hash của file
    
    Args:
        filepath: Đường dẫn đến file cần hash
        
    Returns:
        str: SHA256 hash string (hex)
        
    Example:
        >>> hash_value = calculate_sha256("file.exe")
        >>> print(hash_value)
        "a1b2c3d4..."
    """
    sha256_hash = hashlib.sha256()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


def calculate_md5(filepath: str) -> str:
    """
    Calculate MD5 hash của file
    
    Args:
        filepath: Đường dẫn đến file cần hash
        
    Returns:
        str: MD5 hash string (hex)
        
    Example:
        >>> hash_value = calculate_md5("file.exe")
        >>> print(hash_value)
        "5d41402abc4b2a76b9719d911017c592"
    """
    md5_hash = hashlib.md5()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    return md5_hash.hexdigest()


def generate_unique_filename(original_filename: str) -> str:
    """
    Generate unique filename để tránh conflict khi upload
    
    Args:
        original_filename: Tên file gốc
        
    Returns:
        str: Unique filename với UUID prefix
        
    Example:
        >>> unique_name = generate_unique_filename("test.exe")
        >>> print(unique_name)
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890_test.exe"
    """
    file_ext = Path(original_filename).suffix
    unique_id = str(uuid.uuid4())
    return f"{unique_id}{file_ext}"


def format_file_size(bytes_size: int) -> str:
    """
    Format file size từ bytes sang human-readable format
    
    Args:
        bytes_size: File size in bytes
        
    Returns:
        str: Formatted string (e.g., "1.5 MB", "2.0 GB")
        
    Example:
        >>> format_file_size(1048576)
        "1.0 MB"
        >>> format_file_size(2147483648)
        "2.0 GB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename để loại bỏ các ký tự không hợp lệ
    
    Args:
        filename: Tên file cần sanitize
        
    Returns:
        str: Sanitized filename
        
    Example:
        >>> sanitize_filename("test<script>.exe")
        "test_script_.exe"
    """
    # Loại bỏ các ký tự không hợp lệ
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Loại bỏ leading/trailing spaces và dots
    filename = filename.strip(' .')
    
    return filename


def get_file_extension(filename: str) -> str:
    """
    Get file extension từ filename
    
    Args:
        filename: Tên file
        
    Returns:
        str: File extension (lowercase, không có dot)
        
    Example:
        >>> get_file_extension("test.exe")
        "exe"
        >>> get_file_extension("document.PDF")
        "pdf"
    """
    return Path(filename).suffix.lower().lstrip('.')


def is_safe_path(path: str, base_path: Path) -> bool:
    """
    Kiểm tra path có an toàn không (prevent path traversal attacks)
    
    Args:
        path: Path cần kiểm tra
        base_path: Base path được phép truy cập
        
    Returns:
        bool: True nếu path an toàn, False nếu không
        
    Example:
        >>> is_safe_path("uploads/file.exe", Path("uploads"))
        True
        >>> is_safe_path("../../../etc/passwd", Path("uploads"))
        False
    """
    try:
        resolved_path = (base_path / path).resolve()
        return resolved_path.is_relative_to(base_path.resolve())
    except (ValueError, OSError):
        return False


def get_current_timestamp() -> datetime:
    """
    Get current UTC timestamp
    
    Returns:
        datetime: Current UTC datetime
        
    Example:
        >>> timestamp = get_current_timestamp()
        >>> print(timestamp)
        2024-01-01 12:00:00
    """
    return datetime.utcnow()


def validate_file_size(file_size: int, max_size: int) -> bool:
    """
    Validate file size có trong giới hạn không
    
    Args:
        file_size: File size in bytes
        max_size: Maximum allowed size in bytes
        
    Returns:
        bool: True nếu file size hợp lệ, False nếu không
        
    Example:
        >>> validate_file_size(1048576, 2147483648)
        True
        >>> validate_file_size(3221225472, 2147483648)
        False
    """
    return file_size <= max_size

