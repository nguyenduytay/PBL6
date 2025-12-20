"""
Scan endpoints - File upload và analysis
"""
import os
import sys
import time
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, Query

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.services.analyzer_service import AnalyzerService
from app.schemas.scan import ScanResult

router = APIRouter()
analyzer_service = AnalyzerService()

@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """
    API Upload & Scan File
    
    - Upload file lên server
    - Chạy toàn bộ các module: Hash, YARA, EMBER
    - Trả về kết quả phân tích
    """
    start_time = time.time()
    
    # Save uploaded file
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)
    
    try:
        # Phân tích và lưu vào database
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath),
            file.filename
        )
        
        # Tạo response
        result = ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=analysis_data.get("yara_matches", []),
            pe_info=analysis_data.get("pe_info"),
            suspicious_strings=analysis_data.get("suspicious_strings", []),
            capabilities=analysis_data.get("capabilities", []),
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        # Cleanup
        if filepath.exists():
            os.remove(filepath)

@router.post("/yara", response_model=ScanResult)
async def scan_yara(file: UploadFile = File(...)):
    """
    API Quét YARA (Nhanh)
    
    - Chỉ sử dụng luật YARA để phát hiện malware
    - Phù hợp phân tích nhanh theo signatures
    """
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        f.write(await file.read())
    
    try:
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath), file.filename, scan_modules=["yara"]
        )
        return ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=analysis_data.get("yara_matches", []),
            pe_info=analysis_data.get("pe_info"),
            suspicious_strings=analysis_data.get("suspicious_strings", []),
            capabilities=analysis_data.get("capabilities", []),
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"YARA error: {str(e)}")
    finally:
        if filepath.exists(): os.remove(filepath)

@router.post("/ember", response_model=ScanResult)
async def scan_ember(file: UploadFile = File(...)):
    """
    API Quét EMBER AI (Chuyên sâu)
    
    - Sử dụng Machine Learning để phát hiện mẫu lạ
    - Phân tích file thực thi (PE Files) không cần signature
    """
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        f.write(await file.read())
    
    try:
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath), file.filename, scan_modules=["ember"]
        )
        return ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=[],
            pe_info=analysis_data.get("pe_info"),
            suspicious_strings=[],
            capabilities=[],
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EMBER error: {str(e)}")
    finally:
        if filepath.exists(): os.remove(filepath)

