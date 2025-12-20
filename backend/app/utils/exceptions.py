"""
Exceptions Module - Custom exceptions
Các exception tùy chỉnh: BusinessException, ValidationException, NotFoundException, etc.
"""
from fastapi import HTTPException, status


class BusinessException(HTTPException):
    """
    Business Logic Exception - Exception cho business rule violations
    
    Sử dụng khi business logic không được thỏa mãn
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class ValidationException(HTTPException):
    """
    Validation Exception - Exception cho input validation errors
    
    Sử dụng khi input không hợp lệ
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY):
        super().__init__(status_code=status_code, detail=detail)


class NotFoundException(HTTPException):
    """
    Not Found Exception - Exception khi resource không tồn tại
    """
    
    def __init__(self, detail: str, status_code: int = status.HTTP_404_NOT_FOUND):
        super().__init__(status_code=status_code, detail=detail)


class UnauthorizedException(HTTPException):
    """
    Unauthorized Exception - Exception khi user chưa authenticate
    """
    
    def __init__(self, detail: str = "Authentication required", status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)


class ForbiddenException(HTTPException):
    """
    Forbidden Exception - Exception khi user không có quyền
    """
    
    def __init__(self, detail: str = "Insufficient permissions", status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)


class InternalServerException(HTTPException):
    """
    Internal Server Exception - Exception cho lỗi hệ thống
    """
    
    def __init__(self, detail: str = "Internal server error", status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        super().__init__(status_code=status_code, detail=detail)

