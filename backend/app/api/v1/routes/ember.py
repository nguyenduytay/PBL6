"""
EMBER Endpoints - API quét malware bằng EMBER AI model
"""
import os
import time
from fastapi import APIRouter, File, UploadFile, HTTPException
from typing import Dict, Any

from app.core.config import settings
from app.services.analyzer_service import AnalyzerService
from app.schemas.scan import ScanResult

router = APIRouter()
analyzer_service = AnalyzerService()  # Service phân tích malware

@router.post("/scan", response_model=ScanResult)
async def scan_ember_only(file: UploadFile = File(...)):
    """
    Quét file CHỈ sử dụng Model EMBER AI
    
    - Upload file
    - Trích xuất đặc trưng (LIEF)
    - Dự đoán bằng Model LightGBM
    """
    
    # Lưu file upload
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)
    
    try:
        # Chỉ quét bằng EMBER AI (không chạy Hash hay YARA)
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath),
            file.filename,
            scan_modules=["ember"]
        )
        
        # Tạo response (YARA matches = [] vì chỉ chạy EMBER)
        result = ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=[],  # Chỉ quét EMBER, không có YARA matches
            pe_info=analysis_data.get("pe_info"),
            suspicious_strings=[],
            capabilities=[],
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EMBER Analysis error: {str(e)}")
    finally:
        # Xóa file tạm sau khi xử lý
        if filepath.exists():
            os.remove(filepath)
