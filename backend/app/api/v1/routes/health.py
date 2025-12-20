"""
Health check endpoints - API kiểm tra trạng thái hệ thống
"""
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("")
async def health_check():
    """Kiểm tra trạng thái hệ thống và số lượng YARA rules đã load"""
    yara_rules = settings.get_yara_rules()
    return {
        "status": "healthy",
        "yara_rules_loaded": yara_rules is not None,  # YARA rules đã load chưa
        "yara_rule_count": len(list(yara_rules)) if yara_rules else 0  # Số lượng rules
    }

