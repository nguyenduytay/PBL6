"""
Scan endpoints - File upload và analysis
"""
import os
import sys
import time
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, UploadFile, HTTPException

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
    API endpoint để quét file
    
    - Upload file
    - Phân tích static (YARA, Hash, PE)
    - Trả về kết quả JSON
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
            analysis_time=analysis_data.get("analysis_time", 0.0)
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        # Cleanup
        if filepath.exists():
            os.remove(filepath)

