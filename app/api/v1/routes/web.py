"""
Web routes - HTML pages và form handling
"""
import os
import sys
import time
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Request, File, UploadFile
from fastapi.responses import HTMLResponse

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.core.dependencies import render_template
from app.services.analyzer_service import AnalyzerService

router = APIRouter()
analyzer_service = AnalyzerService()

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Trang chủ - Dashboard"""
    return HTMLResponse(content=render_template("dashboard.html"))

@router.get("/submit", response_class=HTMLResponse)
async def submit_page(request: Request):
    """Trang submit file"""
    return HTMLResponse(content=render_template("submit.html"))

@router.get("/analyses", response_class=HTMLResponse)
async def analyses_list(request: Request):
    """Danh sách các phân tích"""
    return HTMLResponse(content=render_template("analyses.html"))

@router.post("/submit", response_class=HTMLResponse)
async def submit_post(
    request: Request,
    file: Optional[UploadFile] = File(None),
    folderFiles: Optional[List[UploadFile]] = File(None)
):
    """Xử lý POST request từ form upload"""
    try:
        # Xử lý upload file đơn lẻ
        if file and file.filename and file.filename != "":
            filepath = settings.UPLOAD_FOLDER / file.filename
            
            # Save file
            content = await file.read()
            with open(filepath, "wb") as f:
                f.write(content)
            
            try:
                # Phân tích và lưu vào database
                analysis_data = await analyzer_service.analyze_and_save(
                    str(filepath),
                    file.filename
                )
                
                return HTMLResponse(content=render_template(
                    "result.html",
                    filename=file.filename,
                    result=analysis_data.get("results", []),
                    elapsed=analysis_data.get("analysis_time", 0.0),
                    analysis_type="single_file",
                    analysis_id=analysis_data.get("id")
                ))
            finally:
                # Cleanup uploaded file
                if filepath.exists():
                    os.remove(filepath)
        
        # Xử lý upload folder (multiple files)
        elif folderFiles and len(folderFiles) > 0:
            # Kiểm tra file đầu tiên có filename không
            if folderFiles[0].filename == "":
                return HTMLResponse(content="❌ No folder selected", status_code=400)
            
            temp_dir = tempfile.mkdtemp()
            file_paths = []
            
            try:
                for uploaded_file in folderFiles:
                    if uploaded_file.filename:
                        # Preserve folder structure
                        rel_path = uploaded_file.filename
                        filepath = Path(temp_dir) / rel_path
                        # Tạo thư mục nếu cần
                        filepath.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Save file
                        content = await uploaded_file.read()
                        with open(filepath, "wb") as f:
                            f.write(content)
                        file_paths.append(str(filepath))
                
                if file_paths:
                    # Phân tích folder (chưa lưu vào DB cho folder)
                    start_time = time.time()
                    result = await analyzer_service.analyze_folder(file_paths)
                    elapsed = time.time() - start_time
                    
                    return HTMLResponse(content=render_template(
                        "result.html",
                        filename=f"Folder ({len(file_paths)} files)",
                        result=result,
                        elapsed=elapsed,
                        analysis_type="folder"
                    ))
                else:
                    return HTMLResponse(content="❌ No files in folder", status_code=400)
            finally:
                # Cleanup temp directory
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        else:
            return HTMLResponse(content="❌ No file or folder uploaded", status_code=400)
            
    except Exception as e:
        import traceback
        error_msg = f"❌ Error: {str(e)}\n{traceback.format_exc()}"
        print(error_msg)
        return HTMLResponse(content=error_msg, status_code=500)

