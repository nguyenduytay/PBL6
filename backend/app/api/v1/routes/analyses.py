"""
Analyses endpoints - API quản lý lịch sử phân tích
"""
import os
import sys
from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException

# Thêm project root vào path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.services.analysis_service import AnalysisService
from app.schemas.analysis import AnalysisResponse

router = APIRouter()
analysis_service = AnalysisService()  # Service quản lý analyses

@router.get("")
async def get_analyses(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Lấy danh sách analyses với pagination
    
    - limit: Số lượng kết quả (1-1000)
    - offset: Vị trí bắt đầu
    
    Returns:
        {
            "items": List[AnalysisResponse],
            "total": int,
            "limit": int,
            "offset": int
        }
    """
    try:
        # Lấy danh sách analyses với pagination
        analyses = await analysis_service.get_all(limit=limit, offset=offset)
        total = await analysis_service.count_all()  # Tổng số analyses
        
        return {
            "items": analyses,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analyses: {str(e)}")

@router.get("/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Lấy chi tiết một analysis theo ID"""
    try:
        analysis = await analysis_service.get_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analysis: {str(e)}")

@router.get("/sha256/{sha256}")
async def get_analysis_by_sha256(sha256: str):
    """Lấy analysis theo hash SHA256"""
    try:
        analysis = await analysis_service.get_by_sha256(sha256)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching analysis: {str(e)}")

@router.get("/stats/summary")
async def get_statistics():
    """Lấy thống kê tổng quan: tổng số, malware, file sạch, 24h gần đây"""
    try:
        stats = await analysis_service.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching statistics: {str(e)}")

@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: int):
    """Xóa một analysis"""
    try:
        # Kiểm tra analysis có tồn tại không
        analysis = await analysis_service.get_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Xóa analysis và các dữ liệu liên quan (yara_matches, ratings)
        deleted = await analysis_service.delete(analysis_id)
        if not deleted:
            raise HTTPException(status_code=500, detail="Failed to delete analysis")
        
        return {"message": "Analysis deleted successfully", "id": analysis_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting analysis: {str(e)}")

