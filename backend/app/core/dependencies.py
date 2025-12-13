"""
Dependencies cho FastAPI - Shared dependencies
"""
from fastapi import Request

def get_yara_rules():
    """Get YARA rules instance"""
    from app.core.config import settings
    return settings.get_yara_rules()

def get_static_analyzer():
    """Get Static Analyzer instance"""
    from app.core.config import settings
    return settings.get_static_analyzer()

