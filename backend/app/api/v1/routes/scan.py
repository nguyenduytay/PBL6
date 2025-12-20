"""
Scan endpoints - API upload và quét file malware
"""
import os
import sys
import time
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, Query

# Thêm project root vào path để import modules
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.services.analyzer_service import AnalyzerService
from app.schemas.scan import ScanResult

router = APIRouter()
analyzer_service = AnalyzerService()  # Service xử lý phân tích malware

@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """
    API Upload & Scan File
    
    - Upload file lên server
    - Chạy toàn bộ các module: Hash, YARA, EMBER
    - Trả về kết quả phân tích
    """
    # Kiểm tra tên file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    # Lưu file upload vào thư mục tạm
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)
    
    try:
        # Phân tích file (Hash + YARA + EMBER) và lưu vào database
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath),
            file.filename
        )
        
        # Tạo response từ kết quả phân tích
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
        # Xóa file tạm sau khi xử lý xong
        if filepath.exists():
            os.remove(filepath)

@router.post("/yara", response_model=ScanResult)
async def scan_yara(file: UploadFile = File(...)):
    """
    API Quét YARA (Nhanh)
    
    - Chỉ sử dụng luật YARA để phát hiện malware
    - Phù hợp phân tích nhanh theo signatures
    """
    # Kiểm tra tên file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    # Lưu file upload
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        f.write(await file.read())
    
    try:
        # Chỉ quét bằng YARA (không chạy Hash hay EMBER)
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
    - Chỉ chạy EMBER model, không chạy YARA hoặc hash check
    - Chỉ chấp nhận file PE (Portable Executable): .exe, .dll, .sys, .scr, v.v.
    """
    # Kiểm tra tên file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    # Lưu file upload
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        f.write(await file.read())
    
    try:
        # Kiểm tra file có phải PE không (EMBER chỉ phân tích PE files)
        from app.ml.ember_model import EmberModel
        ember_model = EmberModel()
        is_pe, pe_error_detail = ember_model.is_pe_file(str(filepath))
        if not is_pe:
            error_detail = "File is not a valid PE file. EMBER only analyzes PE files (Portable Executable: .exe, .dll, .sys, .scr, etc.). PE files must start with 'MZ' header."
            if pe_error_detail:
                error_detail += f" Details: {pe_error_detail}"
            raise HTTPException(
                status_code=400, 
                detail=error_detail
            )
        
        # Chỉ quét bằng EMBER AI (không chạy Hash hay YARA)
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath), file.filename, scan_modules=["ember"]
        )
        
        # Lấy dữ liệu từ kết quả phân tích (PE info, strings từ static analyzer)
        return ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=analysis_data.get("yara_matches", []),  # Từ static_analysis
            pe_info=analysis_data.get("pe_info"),  # Từ static_analysis
            suspicious_strings=analysis_data.get("suspicious_strings", []),  # Từ static_analysis
            capabilities=analysis_data.get("capabilities", []),  # Từ static_analysis
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])  # Chứa kết quả EMBER
        )
    except HTTPException:
        # Re-raise HTTPException (đã được xử lý ở trên)
        raise
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        error_detail = f"EMBER analysis error: {str(e)}"
        # Log chi tiết lỗi
        print(f"[ERROR] EMBER API error for {file.filename}:")
        print(error_traceback)
        raise HTTPException(
            status_code=500, 
            detail=f"{error_detail}. Check server logs for more details."
        )
    finally:
        if filepath.exists(): os.remove(filepath)

