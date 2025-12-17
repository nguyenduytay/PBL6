"""
Configuration Module - Application settings và configuration management
Module này quản lý tất cả các cấu hình của ứng dụng, load từ environment variables
"""
import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
import yara
from dotenv import load_dotenv

# Load environment variables từ .env file
load_dotenv()

# Base directory - Thư mục gốc của project
BASE_DIR = Path(__file__).parent.parent.parent

# Global instances - Sẽ được khởi tạo ở startup
yara_rules: Optional[yara.Rules] = None
static_analyzer = None


class Settings:
    """
    Application Settings - Quản lý tất cả cấu hình của ứng dụng
    
    Load từ environment variables hoặc .env file, fallback về default values
    """
    
    # Application Info
    APP_NAME: str = os.getenv("APP_NAME", "Malware Detector API")
    APP_VERSION: str = os.getenv("APP_VERSION", "2.0.0")
    APP_DESCRIPTION: str = os.getenv(
        "APP_DESCRIPTION",
        "Advanced malware analysis platform với static và dynamic analysis"
    )
    
    # Server Configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "5000"))
    
    # API Configuration
    API_V1_STR: str = os.getenv("API_V1_STR", "/api")
    DOCS_URL: str = os.getenv("DOCS_URL", "/api/docs")
    REDOC_URL: str = os.getenv("REDOC_URL", "/api/redoc")
    
    # Database Configuration
    DB_HOST: str = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "sa")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "123456")
    DB_NAME: str = os.getenv("DB_NAME", "malwaredetection")
    
    # Security Configuration
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "your-secret-key-change-in-production"
    )
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Paths Configuration
    UPLOAD_FOLDER: Path = BASE_DIR / "uploads"
    YARA_RULES_PATH: Path = BASE_DIR / "yara_rules" / "rules" / "index.yar"
    LOGS_FOLDER: Path = BASE_DIR / "logs"
    
    # Upload Limits
    MAX_UPLOAD_SIZE_GB: int = int(os.getenv("MAX_UPLOAD_SIZE_GB", "2"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_GB * 1024 * 1024 * 1024
    
    # CORS Configuration
    # Load từ environment variable hoặc dùng default
    CORS_ORIGINS: list = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"
    ).split(",") if os.getenv("CORS_ORIGINS") else [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: Optional[str] = os.getenv("LOG_FILE", None)
    
    def __init__(self):
        """
        Initialize settings và tạo các thư mục cần thiết
        """
        # Tạo các thư mục cần thiết
        self.UPLOAD_FOLDER.mkdir(exist_ok=True)
        self.LOGS_FOLDER.mkdir(exist_ok=True)
    
    @classmethod
    def load_yara_rules(cls) -> Optional[yara.Rules]:
        """
        Load YARA rules từ file
        
        Returns:
            Optional[yara.Rules]: YARA rules instance nếu load thành công, None nếu lỗi
            
        Example:
            >>> rules = Settings.load_yara_rules()
            >>> if rules:
            ...     matches = rules.match("file.exe")
        """
        global yara_rules
        
        # Nếu đã load rồi, return ngay
        if yara_rules is not None:
            return yara_rules
        
        try:
            settings = cls()
            if settings.YARA_RULES_PATH.exists():
                yara_rules = yara.compile(filepath=str(settings.YARA_RULES_PATH))
                rule_count = len(list(yara_rules)) if yara_rules else 0
                print(f"[OK] YARA rules loaded: {rule_count} rules")
                return yara_rules
            else:
                print(f"[WARN] YARA rules file not found: {settings.YARA_RULES_PATH}")
                return None
        except Exception as e:
            print(f"[WARN] Warning loading YARA rules: {e}")
            return None
    
    @classmethod
    def get_yara_rules(cls) -> Optional[yara.Rules]:
        """
        Get YARA rules instance - Lazy loading nếu chưa load
        
        Returns:
            Optional[yara.Rules]: YARA rules instance
            
        Example:
            >>> rules = Settings.get_yara_rules()
            >>> if rules:
            ...     matches = rules.match("file.exe")
        """
        return yara_rules if yara_rules is not None else cls.load_yara_rules()
    
    @classmethod
    def init_static_analyzer(cls):
        """
        Initialize Static Analyzer instance
        
        Returns:
            Static Analyzer instance hoặc None nếu lỗi
            
        Example:
            >>> analyzer = Settings.init_static_analyzer()
            >>> if analyzer:
            ...     result = analyzer.analyze("file.exe")
        """
        global static_analyzer
        
        if static_analyzer is None:
            try:
                from src.Analysis.StaticAnalyzer import create_static_analyzer
                settings = cls()
                rules_path = str(settings.YARA_RULES_PATH) if settings.YARA_RULES_PATH.exists() else None
                static_analyzer = create_static_analyzer(rules_path)
                print("[OK] Static Analyzer initialized")
            except Exception as e:
                print(f"[WARN] Failed to initialize Static Analyzer: {e}")
                static_analyzer = None
        
        return static_analyzer
    
    @classmethod
    def get_static_analyzer(cls):
        """
        Get Static Analyzer instance - Lazy loading nếu chưa init
        
        Returns:
            Static Analyzer instance hoặc None nếu lỗi
            
        Example:
            >>> analyzer = Settings.get_static_analyzer()
            >>> if analyzer:
            ...     result = analyzer.analyze("file.exe")
        """
        return static_analyzer if static_analyzer is not None else cls.init_static_analyzer()


# Global settings instance
settings = Settings()


