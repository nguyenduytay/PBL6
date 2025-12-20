"""
Validators - Validation input
Kiểm tra file size, filename, file path để đảm bảo an toàn
"""
from pathlib import Path
from typing import List, Optional
from app.utils.file_utils import get_file_extension, sanitize_filename


def validate_file_size(file_size: int, max_size: int) -> bool:
    """
    Kiểm tra file size có trong giới hạn không
    
    Args:
        file_size: File size in bytes
        max_size: Maximum allowed size in bytes
        
    Returns:
        bool: True nếu file size hợp lệ, False nếu không
    """
    return file_size <= max_size


def validate_filename(filename: str, allowed_extensions: Optional[List[str]] = None) -> tuple[bool, Optional[str]]:
    """
    Kiểm tra filename có hợp lệ không
    
    Args:
        filename: Tên file cần kiểm tra
        allowed_extensions: Danh sách extension được phép (None = tất cả)
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not filename or not filename.strip():
        return False, "Filename không được rỗng"
    
    # Kiểm tra extension nếu có yêu cầu
    if allowed_extensions:
        ext = get_file_extension(filename)
        if ext not in [e.lower().lstrip('.') for e in allowed_extensions]:
            return False, f"File extension không được phép. Chỉ chấp nhận: {', '.join(allowed_extensions)}"
    
    # Kiểm tra tên file sau khi sanitize
    sanitized = sanitize_filename(filename)
    if sanitized != filename:
        return False, "Filename chứa ký tự không hợp lệ"
    
    return True, None


def validate_file_path(file_path: str, base_path: Path) -> tuple[bool, Optional[str]]:
    """
    Kiểm tra file path có an toàn không
    
    Args:
        file_path: Đường dẫn file
        base_path: Base path được phép
        
    Returns:
        tuple: (is_valid, error_message)
    """
    from app.utils.file_utils import is_safe_path
    
    if not is_safe_path(file_path, base_path):
        return False, "File path không an toàn (path traversal detected)"
    
    return True, None

