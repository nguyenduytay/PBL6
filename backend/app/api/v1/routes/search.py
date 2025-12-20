"""
Search endpoints - Tìm kiếm analyses
"""
import os
import sys
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Query, HTTPException

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.services.analysis_service import AnalysisService
from app.schemas.analysis import AnalysisResponse


router = APIRouter()
analysis_service = AnalysisService()


@router.get("/analyses")
async def search_analyses(
    q: str = Query(..., min_length=1, description="Search query for filename, SHA256, or MD5"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """
    Tìm kiếm kết quả phân tích theo tên file, SHA256, hoặc MD5
    
    - q: Từ khóa tìm kiếm (tên file, SHA256, MD5)
    - limit: Số lượng kết quả (1-100)
    - offset: Vị trí bắt đầu
    
    Ví dụ:
    - Tìm theo tên: q=test.exe
    - Tìm theo hash: q=abc123...
    """
    try:
        if not q or not q.strip():
            raise HTTPException(status_code=400, detail="Search query cannot be empty")
        
        query = q.strip()
        
        # Lấy kết quả và tổng số lượng khớp
        results = await analysis_repo.search(query, limit=limit, offset=offset)
        total = await analysis_repo.count_search(query)
        
        if not results:
            # Trả về danh sách trống nếu không tìm thấy
            return {
                "items": [],
                "total": 0,
                "limit": limit,
                "offset": offset
            }
        
        # Chuyển đổi sang model response, xử lý các trường thiếu
        response_list = []
        for r in results:
            try:
                # Xử lý các trường thời gian nếu là chuỗi
                created_at = r.get('created_at')
                if isinstance(created_at, str):
                    try:
                        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    except:
                        created_at = datetime.now()
                elif created_at is None:
                    created_at = datetime.now()
                
                upload_time = r.get('upload_time')
                if upload_time and isinstance(upload_time, str):
                    try:
                        upload_time = datetime.fromisoformat(upload_time.replace('Z', '+00:00'))
                    except:
                        upload_time = None
                
                # Đảm bảo tất cả các trường bắt buộc đều có dữ liệu
                response_data = {
                    'id': r.get('id'),
                    'filename': r.get('filename', ''),
                    'sha256': r.get('sha256'),
                    'md5': r.get('md5'),
                    'file_size': r.get('file_size'),
                    'upload_time': upload_time,
                    'analysis_time': float(r.get('analysis_time', 0.0) or 0.0),
                    'malware_detected': bool(r.get('malware_detected', False)),
                    'yara_matches': r.get('yara_matches', []) or [],
                    'pe_info': r.get('pe_info'),
                    'suspicious_strings': r.get('suspicious_strings', []) or [],
                    'capabilities': r.get('capabilities', []) or [],
                    'created_at': created_at or datetime.now()
                }
                response_list.append(AnalysisResponse(**response_data))
            except Exception as e:
                # Bỏ qua kết quả không hợp lệ và in lỗi để debug
                import traceback
                traceback.print_exc()
                continue
        
        return {
            "items": response_list,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching analyses: {str(e)}")

