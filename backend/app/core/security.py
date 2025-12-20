"""
Security Module - Bảo mật và xác thực
JWT tokens, password hashing (bcrypt), role-based access control (RBAC)
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from enum import Enum

# Password hashing context - Sử dụng bcrypt để hash passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration - Cấu hình cho JWT tokens
# TODO: Nên lấy từ environment variables trong production
SECRET_KEY = "your-secret-key-change-in-production"  # Thay đổi trong production
ALGORITHM = "HS256"  # Thuật toán mã hóa JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Thời gian hết hạn của access token (phút)

# HTTP Bearer token scheme cho FastAPI
security = HTTPBearer()


class Role(str, Enum):
    """
    User roles enum - Định nghĩa các vai trò người dùng trong hệ thống
    
    Attributes:
        ADMIN: Quản trị viên - có quyền cao nhất
        MANAGER: Quản lý - có quyền quản lý một số tài nguyên
        USER: Người dùng thường - có quyền cơ bản
        GUEST: Khách - quyền hạn chế nhất
    """
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"


def hash_password(password: str) -> str:
    """
    Hash password sử dụng bcrypt
    
    Args:
        password: Password dạng plain text cần hash
        
    Returns:
        str: Hashed password
        
    Example:
        >>> hashed = hash_password("my_password_123")
        >>> verify_password("my_password_123", hashed)
        True
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password với hashed password
    
    Args:
        plain_password: Password dạng plain text
        hashed_password: Hashed password từ database
        
    Returns:
        bool: True nếu password đúng, False nếu sai
        
    Example:
        >>> verify_password("my_password_123", "$2b$12$...")
        True
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Tạo JWT access token
    
    Args:
        data: Dictionary chứa thông tin cần encode vào token (thường là user_id, email, role)
        expires_delta: Thời gian hết hạn tùy chỉnh. Nếu None, dùng ACCESS_TOKEN_EXPIRE_MINUTES
        
    Returns:
        str: JWT token string
        
    Example:
        >>> token = create_access_token({"sub": "user@example.com", "user_id": 1, "role": "user"})
    """
    to_encode = data.copy()
    
    # Tính thời gian hết hạn
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Thêm thời gian hết hạn vào payload
    to_encode.update({"exp": expire})
    # Mã hóa JWT token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode và verify JWT token
    
    Args:
        token: JWT token string cần decode
        
    Returns:
        Optional[Dict[str, Any]]: Payload của token nếu hợp lệ, None nếu không hợp lệ
        
    Raises:
        HTTPException: Nếu token không hợp lệ hoặc đã hết hạn
        
    Example:
        >>> payload = decode_access_token(token)
        >>> user_id = payload.get("user_id")
    """
    try:
        # Giải mã và xác thực JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        # Token không hợp lệ hoặc đã hết hạn
        return None


class JWTBearer(HTTPBearer):
    """
    Custom HTTPBearer để verify JWT token từ Authorization header
    
    Sử dụng trong FastAPI dependencies để bảo vệ các endpoints cần authentication
    """
    
    def __init__(self, auto_error: bool = True):
        """
        Initialize JWTBearer
        
        Args:
            auto_error: Nếu True, tự động raise HTTPException khi token không hợp lệ
        """
        super(JWTBearer, self).__init__(auto_error=auto_error)
    
    async def __call__(self, request) -> Optional[str]:
        """
        Verify JWT token từ Authorization header
        
        Args:
            request: FastAPI Request object
            
        Returns:
            Optional[str]: Token string nếu hợp lệ
            
        Raises:
            HTTPException: Nếu token không hợp lệ hoặc thiếu
        """
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        
        if credentials:
            # Xác thực token
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid authentication token"
                )
            return credentials.credentials
        else:
            # Không có credentials
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization code"
            )
    
    def verify_jwt(self, jwtoken: str) -> bool:
        """
        Verify JWT token có hợp lệ không
        
        Args:
            jwtoken: JWT token string
            
        Returns:
            bool: True nếu token hợp lệ, False nếu không
        """
        is_token_valid: bool = False
        
        try:
            payload = decode_access_token(jwtoken)
            if payload:
                is_token_valid = True
        except Exception:
            is_token_valid = False
        
        return is_token_valid


def require_role(required_role: Role):
    """
    Decorator để kiểm tra role của user
    
    Args:
        required_role: Role tối thiểu cần có để truy cập endpoint
        
    Returns:
        Decorator function
        
    Example:
        @router.get("/admin/users")
        @require_role(Role.ADMIN)
        async def get_all_users():
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # TODO: Implement role checking logic
            # current_user = kwargs.get("current_user")
            # if not current_user or current_user.role != required_role:
            #     raise HTTPException(403, "Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input để prevent XSS attacks
    
    Args:
        input_str: String cần sanitize
        
    Returns:
        str: Sanitized string
        
    Example:
        >>> sanitize_input("<script>alert('xss')</script>")
        "&lt;script&gt;alert('xss')&lt;/script&gt;"
    """
    import html
    return html.escape(input_str.strip())

