"""
Ratings endpoints - API quản lý ratings cho analyses
"""
import os
import sys
from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field

# Thêm project root vào path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.services.rating_service import RatingService

router = APIRouter()
rating_service = RatingService()


class RatingCreate(BaseModel):
    """Schema để tạo rating mới"""
    analysis_id: int = Field(..., ge=1, description="Analysis ID")
    rating: int = Field(..., ge=1, le=5, description="Rating từ 1-5")
    comment: Optional[str] = Field(None, max_length=1000, description="Comment")
    reviewer_name: Optional[str] = Field(None, max_length=100, description="Tên người đánh giá")
    tags: Optional[List[str]] = Field(None, description="Tags")


class RatingUpdate(BaseModel):
    """Schema để cập nhật rating"""
    rating: Optional[int] = Field(None, ge=1, le=5, description="Rating từ 1-5")
    comment: Optional[str] = Field(None, max_length=1000, description="Comment")
    tags: Optional[List[str]] = Field(None, description="Tags")


@router.get("/{analysis_id}")
async def get_ratings(
    analysis_id: int,
    limit: int = Query(50, ge=1, le=100, description="Số lượng kết quả"),
    offset: int = Query(0, ge=0, description="Vị trí bắt đầu")
):
    """
    Lấy danh sách ratings của một analysis
    
    - analysis_id: ID của analysis
    - limit: Số lượng kết quả (1-100)
    - offset: Vị trí bắt đầu
    
    Returns: List[RatingResponse] hoặc {items: [], total, limit, offset}
    """
    try:
        ratings = await rating_service.get_by_analysis_id(analysis_id, limit, offset)
        # Trả về array trực tiếp để tương thích với frontend
        return ratings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching ratings: {str(e)}")


@router.get("/stats/{analysis_id}")
async def get_rating_stats(analysis_id: int):
    """
    Lấy thống kê ratings của một analysis
    
    - analysis_id: ID của analysis
    
    Returns:
        {
            "total": int,
            "average": float,
            "min_rating": int,
            "max_rating": int,
            "distribution": Dict[str, int]  # {rating: count}
        }
    """
    try:
        stats = await rating_service.get_stats(analysis_id)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching rating stats: {str(e)}")


@router.post("")
async def create_rating(rating_data: RatingCreate):
    """Tạo rating mới"""
    try:
        rating_id = await rating_service.create(
            analysis_id=rating_data.analysis_id,
            rating=rating_data.rating,
            comment=rating_data.comment,
            reviewer_name=rating_data.reviewer_name,
            tags=rating_data.tags
        )
        return {
            "id": rating_id,
            "message": "Rating created successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating rating: {str(e)}")


@router.put("/{rating_id}")
async def update_rating(rating_id: int, rating_data: RatingUpdate):
    """Cập nhật rating"""
    try:
        success = await rating_service.update(
            rating_id=rating_id,
            rating=rating_data.rating,
            comment=rating_data.comment,
            tags=rating_data.tags
        )
        if not success:
            raise HTTPException(status_code=404, detail="Rating not found")
        return {
            "id": rating_id,
            "message": "Rating updated successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating rating: {str(e)}")


@router.delete("/{rating_id}")
async def delete_rating(rating_id: int):
    """Xóa rating"""
    try:
        success = await rating_service.delete(rating_id)
        if not success:
            raise HTTPException(status_code=404, detail="Rating not found")
        return {
            "id": rating_id,
            "message": "Rating deleted successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting rating: {str(e)}")

