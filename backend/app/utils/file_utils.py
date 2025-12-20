"""
File Utils - Xử lý file
Tính hash (SHA256, MD5), sanitize filename, format file size, kiểm tra path an toàn
"""
import hashlib
import os
from pathlib import Path
from typing import Optional
import uuid
from datetime import datetime


def calculate_sha256(filepath: str) -> str:
    """
    Tính SHA256 hash của file
    
    Args:
        filepath: Đường dẫn đến file cần hash
        
    Returns:
        str: SHA256 hash string (hex)
    """
    sha256_hash = hashlib.sha256()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


def calculate_md5(filepath: str) -> str:
    """
    Tính MD5 hash của file
    
    Args:
        filepath: Đường dẫn đến file cần hash
        
    Returns:
        str: MD5 hash string (hex)
    """
    md5_hash = hashlib.md5()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    return md5_hash.hexdigest()


def generate_unique_filename(original_filename: str) -> str:
    """
    Tạo tên file unique để tránh conflict khi upload
    
    Args:
        original_filename: Tên file gốc
        
    Returns:
        str: Unique filename với UUID prefix
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
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """
    Làm sạch filename để loại bỏ các ký tự không hợp lệ
    
    Args:
        filename: Tên file cần sanitize
        
    Returns:
        str: Sanitized filename
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
    Lấy file extension từ filename
    
    Args:
        filename: Tên file
        
    Returns:
        str: File extension (lowercase, không có dot)
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
    """
    try:
        resolved_path = (base_path / path).resolve()
        return resolved_path.is_relative_to(base_path.resolve())
    except (ValueError, OSError):
        return False


def get_current_timestamp() -> datetime:
    """
    Lấy current UTC timestamp
    
    Returns:
        datetime: Current UTC datetime
    """
    return datetime.utcnow()

