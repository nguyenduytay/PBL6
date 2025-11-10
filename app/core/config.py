"""
Configuration settings cho ứng dụng
"""
import os
from pathlib import Path
from typing import Optional
import yara

# Base directory
BASE_DIR = Path(__file__).parent.parent.parent

# Upload folder
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Templates folder - Using new structure
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"

# Static files folder - Using new structure
STATIC_DIR = BASE_DIR / "frontend" / "static"

# YARA rules path
YARA_RULES_PATH = BASE_DIR / "yara_rules" / "rules" / "index.yar"

# YARA rules instance (sẽ được load ở startup)
yara_rules: Optional[yara.Rules] = None

# Static Analyzer instance
static_analyzer = None

# Application settings
class Settings:
    """Application settings"""
    APP_NAME: str = "Malware Detector API"
    APP_VERSION: str = "2.0.0"
    APP_DESCRIPTION: str = "Advanced malware analysis platform với static và dynamic analysis"
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 5000
    
    # API settings
    API_V1_STR: str = "/api"
    DOCS_URL: str = "/api/docs"
    REDOC_URL: str = "/api/redoc"
    
    # Paths
    UPLOAD_FOLDER: Path = UPLOAD_FOLDER
    TEMPLATES_DIR: Path = TEMPLATES_DIR
    STATIC_DIR: Path = STATIC_DIR
    YARA_RULES_PATH: Path = YARA_RULES_PATH
    
    @classmethod
    def load_yara_rules(cls) -> Optional[yara.Rules]:
        """Load YARA rules từ file"""
        global yara_rules
        if yara_rules is not None:
            return yara_rules
            
        try:
            if cls.YARA_RULES_PATH.exists():
                yara_rules = yara.compile(filepath=str(cls.YARA_RULES_PATH))
                rule_count = len(list(yara_rules)) if yara_rules else 0
                print(f"[OK] YARA rules loaded: {rule_count} rules")
                return yara_rules
            else:
                print(f"[WARN] YARA rules file not found: {cls.YARA_RULES_PATH}")
                return None
        except Exception as e:
            print(f"[WARN] Warning loading YARA rules: {e}")
            return None
    
    @classmethod
    def get_yara_rules(cls) -> Optional[yara.Rules]:
        """Get YARA rules instance"""
        return yara_rules if yara_rules is not None else cls.load_yara_rules()
    
    @classmethod
    def init_static_analyzer(cls):
        """Initialize Static Analyzer"""
        global static_analyzer
        if static_analyzer is None:
            try:
                from src.Analysis.StaticAnalyzer import create_static_analyzer
                rules_path = str(cls.YARA_RULES_PATH) if cls.YARA_RULES_PATH.exists() else None
                static_analyzer = create_static_analyzer(rules_path)
            except Exception as e:
                print(f"[WARN] Failed to initialize Static Analyzer: {e}")
                static_analyzer = None
        return static_analyzer
    
    @classmethod
    def get_static_analyzer(cls):
        """Get Static Analyzer instance"""
        return static_analyzer if static_analyzer is not None else cls.init_static_analyzer()

settings = Settings()

