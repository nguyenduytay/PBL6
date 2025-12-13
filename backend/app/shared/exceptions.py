"""
Exceptions Module - Custom exceptions cho ứng dụng
Module này định nghĩa các custom exceptions cho business logic và error handling
"""
from fastapi import HTTPException, status


class BusinessException(HTTPException):
    """
    Business Logic Exception - Exception cho business rule violations
    
    Sử dụng khi business logic không được thỏa mãn (ví dụ: email đã tồn tại, 
    password quá yếu, file quá lớn, etc.)
    
    Example:
        >>> if user_exists(email):
        ...     raise BusinessException("Email already exists")
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        """
        Initialize BusinessException
        
        Args:
            detail: Error message chi tiết
            status_code: HTTP status code (default: 400 Bad Request)
        """
        super().__init__(status_code=status_code, detail=detail)


class ValidationException(HTTPException):
    """
    Validation Exception - Exception cho input validation errors
    
    Sử dụng khi input không hợp lệ (ví dụ: format sai, thiếu required fields, etc.)
    
    Example:
        >>> if not is_valid_email(email):
        ...     raise ValidationException("Invalid email format")
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY):
        """
        Initialize ValidationException
        
        Args:
            detail: Error message chi tiết
            status_code: HTTP status code (default: 422 Unprocessable Entity)
        """
        super().__init__(status_code=status_code, detail=detail)


class NotFoundException(HTTPException):
    """
    Not Found Exception - Exception khi resource không tồn tại
    
    Sử dụng khi không tìm thấy resource (ví dụ: user không tồn tại, 
    analysis không tồn tại, etc.)
    
    Example:
        >>> analysis = await repo.get_by_id(analysis_id)
        >>> if not analysis:
        ...     raise NotFoundException(f"Analysis {analysis_id} not found")
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_404_NOT_FOUND):
        """
        Initialize NotFoundException
        
        Args:
            detail: Error message chi tiết
            status_code: HTTP status code (default: 404 Not Found)
        """
        super().__init__(status_code=status_code, detail=detail)


class UnauthorizedException(HTTPException):
    """
    Unauthorized Exception - Exception khi user chưa authenticate
    
    Sử dụng khi user chưa đăng nhập hoặc token không hợp lệ
    
    Example:
        >>> if not current_user:
        ...     raise UnauthorizedException("Authentication required")
    """
    
    def __init__(self, detail: str = "Authentication required", status_code: int = status.HTTP_401_UNAUTHORIZED):
        """
        Initialize UnauthorizedException
        
        Args:
            detail: Error message chi tiết
            status_code: HTTP status code (default: 401 Unauthorized)
        """
        super().__init__(status_code=status_code, detail=detail)


class ForbiddenException(HTTPException):
    """
    Forbidden Exception - Exception khi user không có quyền
    
    Sử dụng khi user đã authenticate nhưng không có quyền truy cập resource
    
    Example:
        >>> if current_user.role != Role.ADMIN:
        ...     raise ForbiddenException("Admin access required")
    """
    
    def __init__(self, detail: str = "Insufficient permissions", status_code: int = status.HTTP_403_FORBIDDEN):
        """
        Initialize ForbiddenException
        
        Args:
            detail: Error message chi tiết
            status_code: HTTP status code (default: 403 Forbidden)
        """
        super().__init__(status_code=status_code, detail=detail)


class InternalServerException(HTTPException):
    """
    Internal Server Exception - Exception cho lỗi hệ thống
    
    Sử dụng khi có lỗi không mong đợi xảy ra (ví dụ: database error, 
    external service error, etc.)
    
    Example:
        >>> try:
        ...     result = await process_file()
        ... except Exception as e:
        ...     logger.error(f"Unexpected error: {e}")
        ...     raise InternalServerException("An unexpected error occurred")
    """
    
    def __init__(self, detail: str = "Internal server error", status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        """
        Initialize InternalServerException
        
        Args:
            detail: Error message chi tiết (không nên expose chi tiết lỗi cho user)
            status_code: HTTP status code (default: 500 Internal Server Error)
        """
        super().__init__(status_code=status_code, detail=detail)

