"""
Ratings endpoints - Đánh giá và review cho analyses
"""
import os
import sys
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from datetime import datetime

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.services.analysis_service import AnalysisService
from app.database.rating_repository import RatingRepository

router = APIRouter()
analysis_service = AnalysisService()
rating_repo = RatingRepository()


class RatingCreate(BaseModel):
    """Request tạo rating"""
    analysis_id: int
    rating: int = Field(..., ge=1, le=5, description="Rating từ 1-5 sao")
    comment: Optional[str] = Field(None, max_length=1000, description="Comment đánh giá")
    reviewer_name: Optional[str] = Field(None, max_length=100, description="Tên người đánh giá")
    tags: Optional[List[str]] = Field(None, description="Tags: ['accurate', 'false_positive', 'helpful', etc.]")


class RatingUpdate(BaseModel):
    """Request cập nhật rating"""
    rating: Optional[int] = Field(None, ge=1, le=5)
    comment: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = None


class RatingResponse(BaseModel):
    """Response rating"""
    id: int
    analysis_id: int
    rating: int
    comment: Optional[str]
    reviewer_name: Optional[str]
    tags: Optional[List[str]]
    created_at: datetime
    updated_at: Optional[datetime]


class RatingStatsResponse(BaseModel):
    """Thống kê ratings"""
    analysis_id: int
    total_ratings: int
    average_rating: float
    rating_distribution: dict  # {1: count, 2: count, ..., 5: count}
    total_comments: int
    common_tags: List[dict]  # [{"tag": "accurate", "count": 10}]


@router.post("", response_model=RatingResponse)
async def create_rating(rating: RatingCreate):
    """
    Tạo đánh giá cho analysis
    
    - analysis_id: ID của analysis
    - rating: Điểm đánh giá (1-5 sao)
    - comment: Comment đánh giá
    - reviewer_name: Tên người đánh giá
    - tags: Tags đánh giá
    """
    try:
        # Kiểm tra analysis có tồn tại không
        analysis = await analysis_service.get_by_id(rating.analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Tạo rating
        rating_data = {
            "analysis_id": rating.analysis_id,
            "rating": rating.rating,
            "comment": rating.comment,
            "reviewer_name": rating.reviewer_name,
            "tags": rating.tags or [],
            "created_at": datetime.now()
        }
        
        rating_id = await rating_repo.create(rating_data)
        if not rating_id:
            raise HTTPException(status_code=500, detail="Error creating rating")
        
        # Lấy rating vừa tạo
        created_rating = await rating_repo.get_by_id(rating_id)
        if not created_rating:
            raise HTTPException(status_code=500, detail="Error fetching created rating")
        
        return RatingResponse(
            id=created_rating['id'],
            analysis_id=created_rating['analysis_id'],
            rating=created_rating['rating'],
            comment=created_rating.get('comment'),
            reviewer_name=created_rating.get('reviewer_name'),
            tags=created_rating.get('tags', []),
            created_at=created_rating['created_at'],
            updated_at=created_rating.get('updated_at')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating rating: {str(e)}")


@router.get("/{analysis_id}", response_model=List[RatingResponse])
async def get_ratings(
    analysis_id: int,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """
    Lấy danh sách đánh giá của analysis
    
    - analysis_id: ID của analysis
    - limit: Số lượng kết quả
    - offset: Vị trí bắt đầu
    """
    try:
        # Kiểm tra analysis có tồn tại không
        analysis = await analysis_service.get_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Lấy ratings
        ratings = await rating_repo.get_by_analysis_id(analysis_id, limit, offset)
        
        return [
            RatingResponse(
                id=r['id'],
                analysis_id=r['analysis_id'],
                rating=r['rating'],
                comment=r.get('comment'),
                reviewer_name=r.get('reviewer_name'),
                tags=r.get('tags', []),
                created_at=r['created_at'],
                updated_at=r.get('updated_at')
            )
            for r in ratings
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching ratings: {str(e)}")


@router.put("/{rating_id}", response_model=RatingResponse)
async def update_rating(rating_id: int, rating_update: RatingUpdate):
    """
    Cập nhật đánh giá
    
    - rating_id: ID của rating
    - rating_update: Dữ liệu cập nhật
    """
    try:
        # Lấy rating hiện tại
        rating = await rating_repo.get_by_id(rating_id)
        if not rating:
            raise HTTPException(status_code=404, detail="Rating not found")
        
        # Cập nhật
        update_data = rating_update.dict(exclude_unset=True)
        updated_rating = await rating_repo.update(rating_id, update_data)
        
        if not updated_rating:
            raise HTTPException(status_code=500, detail="Error updating rating")
        
        return RatingResponse(
            id=updated_rating['id'],
            analysis_id=updated_rating['analysis_id'],
            rating=updated_rating['rating'],
            comment=updated_rating.get('comment'),
            reviewer_name=updated_rating.get('reviewer_name'),
            tags=updated_rating.get('tags', []),
            created_at=updated_rating['created_at'],
            updated_at=updated_rating.get('updated_at')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating rating: {str(e)}")


@router.delete("/{rating_id}")
async def delete_rating(rating_id: int):
    """
    Xóa đánh giá
    
    - rating_id: ID của rating
    """
    try:
        # Xóa rating
        deleted = await rating_repo.delete(rating_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Rating not found")
        
        return {"message": "Rating deleted successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting rating: {str(e)}")


@router.get("/stats/{analysis_id}", response_model=RatingStatsResponse)
async def get_rating_stats(analysis_id: int):
    """
    Lấy thống kê đánh giá của analysis
    
    - analysis_id: ID của analysis
    """
    try:
        # Kiểm tra analysis có tồn tại không
        analysis = await analysis_service.get_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Lấy thống kê
        stats = await rating_repo.get_statistics(analysis_id)
        
        return RatingStatsResponse(
            analysis_id=analysis_id,
            total_ratings=stats['total_ratings'],
            average_rating=stats['average_rating'],
            rating_distribution=stats['rating_distribution'],
            total_comments=stats['total_comments'],
            common_tags=stats['common_tags']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching rating stats: {str(e)}")

