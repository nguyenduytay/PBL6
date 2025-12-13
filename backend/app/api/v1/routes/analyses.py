"""
Analyses endpoints - Xem lịch sử phân tích
"""
import os
import sys
from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.database.analysis_repository import AnalysisRepository
from app.models.analysis import AnalysisResponse

router = APIRouter()
analysis_repo = AnalysisRepository()

@router.get("", response_model=List[AnalysisResponse])
async def get_analyses(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Lấy danh sách analyses với pagination
    
    - limit: Số lượng kết quả (1-1000)
    - offset: Vị trí bắt đầu
    """
    try:
        analyses = await analysis_repo.get_all(limit=limit, offset=offset)
        return analyses
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analyses: {str(e)}")

@router.get("/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Lấy chi tiết một analysis"""
    try:
        analysis = await analysis_repo.get_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analysis: {str(e)}")

@router.get("/sha256/{sha256}")
async def get_analysis_by_sha256(sha256: str):
    """Lấy analysis theo SHA256"""
    try:
        analysis = await analysis_repo.get_by_sha256(sha256)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analysis: {str(e)}")

@router.get("/stats/summary")
async def get_statistics():
    """Lấy thống kê tổng quan"""
    try:
        stats = await analysis_repo.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching statistics: {str(e)}")

