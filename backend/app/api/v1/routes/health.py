"""
Health check endpoints
"""
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("")
async def health_check():
    """Health check endpoint"""
    yara_rules = settings.get_yara_rules()
    return {
        "status": "healthy",
        "yara_rules_loaded": yara_rules is not None,
        "yara_rule_count": len(list(yara_rules)) if yara_rules else 0
    }

