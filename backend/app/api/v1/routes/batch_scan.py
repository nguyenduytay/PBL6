"""
Batch Scan endpoints - Scan nhiều file hoặc folder
"""
import os
import sys
import zipfile
import tarfile
import asyncio
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks
from pydantic import BaseModel

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.services.analyzer_service import AnalyzerService
from app.services.analysis_service import AnalysisService

router = APIRouter()
analyzer_service = AnalyzerService()
analysis_service = AnalysisService()

# Lưu trữ tạm các batch jobs trong bộ nhớ (nên dùng Redis khi triển khai thực tế)
batch_jobs = {}


class BatchScanRequest(BaseModel):
    """Request để scan folder"""
    folder_path: Optional[str] = None
    file_extensions: Optional[List[str]] = None  # ['exe', 'dll', 'pdf']
    max_files: Optional[int] = 100


class BatchScanResponse(BaseModel):
    """Response cho batch scan"""
    batch_id: str
    total_files: int
    status: str  # 'pending', 'processing', 'completed', 'failed'
    processed: int
    completed: int
    failed: int


class BatchScanResult(BaseModel):
    """Kết quả batch scan"""
    batch_id: str
    status: str
    total_files: int
    processed: int
    completed: int
    failed: int
    results: List[dict]
    errors: List[dict]


async def process_batch_scan(batch_id: str, files: List[Path], batch_jobs: dict):
    """Xử lý quét hàng loạt trong background"""
    batch_jobs[batch_id] = {
        "status": "processing",
        "total_files": len(files),
        "processed": 0,
        "completed": 0,
        "failed": 0,
        "results": [],
        "errors": []
    }
    
    for file_path in files:
        try:
            batch_jobs[batch_id]["processed"] += 1
            
            # Phân tích file
            analysis_data = await analyzer_service.analyze_and_save(
                str(file_path),
                file_path.name
            )
            
            batch_jobs[batch_id]["completed"] += 1
            batch_jobs[batch_id]["results"].append({
                "filename": file_path.name,
                "sha256": analysis_data.get("sha256"),
                "malware_detected": analysis_data.get("malware_detected", False),
                "analysis_id": analysis_data.get("id")
            })
            
        except Exception as e:
            batch_jobs[batch_id]["failed"] += 1
            batch_jobs[batch_id]["errors"].append({
                "filename": file_path.name,
                "error": str(e)
            })
    
    batch_jobs[batch_id]["status"] = "completed"


def extract_archive(file_path: Path, extract_to: Path) -> List[Path]:
    """Giải nén file và trả về danh sách đường dẫn file"""
    extracted_files = []
    
    # Kiểm tra phần mở rộng file
    file_ext = file_path.suffix.lower()
    file_name_lower = file_path.name.lower()
    
    # Xử lý file ZIP
    if file_ext == '.zip' or file_name_lower.endswith('.zip'):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
                for member in zip_ref.namelist():
                    extracted_files.append(extract_to / member)
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid ZIP file: {file_path.name}")
        except Exception as e:
            raise ValueError(f"Error extracting ZIP file: {str(e)}")
    
    # Xử lý file TAR (bao gồm cả nén gz, bz2)
    elif file_ext in ['.tar', '.gz', '.bz2'] or any(file_name_lower.endswith(ext) for ext in ['.tar.gz', '.tar.bz2', '.tgz']):
        try:
            # Xác định chế độ đọc TAR
            mode = 'r'
            if file_ext == '.gz' or file_name_lower.endswith('.tar.gz') or file_name_lower.endswith('.tgz'):
                mode = 'r:gz'
            elif file_ext == '.bz2' or file_name_lower.endswith('.tar.bz2'):
                mode = 'r:bz2'
            
            with tarfile.open(file_path, mode) as tar_ref:
                tar_ref.extractall(extract_to)
                for member in tar_ref.getnames():
                    extracted_files.append(extract_to / member)
        except tarfile.ReadError:
            raise ValueError(f"Invalid TAR file: {file_path.name}")
        except Exception as e:
            raise ValueError(f"Error extracting TAR file: {str(e)}")
    else:
        raise ValueError(f"Unsupported archive format: {file_path.name}. Supported: ZIP, TAR, GZ, BZ2")
    
    # Chỉ lọc lấy file (không lấy thư mục)
    return [f for f in extracted_files if f.is_file()]


@router.post("/folder", response_model=BatchScanResponse)
async def scan_folder(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks = None
):
    """
    Scan cả folder
    
    - folder_path: Đường dẫn folder cần scan
    - file_extensions: Danh sách extension cần scan (mặc định: tất cả)
    - max_files: Số file tối đa (mặc định: 100)
    """
    import uuid
    batch_id = str(uuid.uuid4())
    
    folder_path = Path(request.folder_path) if request.folder_path else settings.UPLOAD_FOLDER
    
    if not folder_path.exists() or not folder_path.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")
    
    # Lấy danh sách files
    all_files = []
    extensions = request.file_extensions or []
    
    for file_path in folder_path.rglob('*'):
        if file_path.is_file():
            if not extensions or file_path.suffix.lower().lstrip('.') in [ext.lower() for ext in extensions]:
                all_files.append(file_path)
    
    # Giới hạn số lượng files
    if request.max_files:
        all_files = all_files[:request.max_files]
    
    if not all_files:
        raise HTTPException(status_code=400, detail="No files found to scan")
    
    # Khởi tạo batch job
    batch_jobs[batch_id] = {
        "status": "pending",
        "total_files": len(all_files),
        "processed": 0,
        "completed": 0,
        "failed": 0,
        "results": [],
        "errors": []
    }
    
    # Chạy batch scan trong background
    background_tasks.add_task(process_batch_scan, batch_id, all_files, batch_jobs)
    
    return BatchScanResponse(
        batch_id=batch_id,
        total_files=len(all_files),
        status="pending",
        processed=0,
        completed=0,
        failed=0
    )


@router.post("/folder-upload", response_model=BatchScanResponse)
async def scan_folder_upload(
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Upload và quét nhiều file từ client
    
    - files: Danh sách file từ thư mục đã chọn
    - Giới hạn kích thước: 2GB (có thể cấu hình)
    """
    import uuid
    batch_id = str(uuid.uuid4())
    
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Check total size before processing
    total_size = 0
    for file in files:
        # Read file size from content-length header if available
        if hasattr(file, 'size') and file.size:
            total_size += file.size
        else:
            # Read content to get size (this will be done anyway)
            content = await file.read()
            total_size += len(content)
            # Reset file pointer for later reading
            await file.seek(0)
    
    if total_size > settings.MAX_UPLOAD_SIZE_BYTES:
        size_gb = total_size / (1024 * 1024 * 1024)
        max_gb = settings.MAX_UPLOAD_SIZE_GB
        raise HTTPException(
            status_code=413,
            detail=f"Total size ({size_gb:.2f} GB) exceeds maximum allowed size ({max_gb} GB)"
        )
    
    # Lưu tất cả file vào thư mục tạm
    temp_folder = settings.UPLOAD_FOLDER / f"temp_{batch_id}"
    temp_folder.mkdir(exist_ok=True)
    
    files_to_scan = []
    for file in files:
        # Làm sạch tên file
        safe_filename = file.filename.replace('/', '_').replace('\\', '_')
        file_path = temp_folder / safe_filename
        
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        if file_path.is_file():
            files_to_scan.append(file_path)
    
    if not files_to_scan:
        raise HTTPException(status_code=400, detail="No files to scan")
    
    # Initialize batch job
    batch_jobs[batch_id] = {
        "status": "pending",
        "total_files": len(files_to_scan),
        "processed": 0,
        "completed": 0,
        "failed": 0,
        "results": [],
        "errors": []
    }
    
    # Run batch scan in background
    if background_tasks:
        background_tasks.add_task(process_batch_scan, batch_id, files_to_scan, batch_jobs)
    
    return BatchScanResponse(
        batch_id=batch_id,
        total_files=len(files_to_scan),
        status="pending",
        processed=0,
        completed=0,
        failed=0
    )


@router.post("/batch", response_model=BatchScanResponse)
async def scan_batch(
    archive: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Quét nhiều file từ file nén (ZIP/TAR)
    
    - Tự động giải nén và quét toàn bộ file bên trong
    - Hỗ trợ: ZIP, TAR, GZ, BZ2
    """
    import uuid
    batch_id = str(uuid.uuid4())
    
    # Read archive content
    content = await archive.read()
    archive_size = len(content)
    
    # Check file size
    if archive_size > settings.MAX_UPLOAD_SIZE_BYTES:
        size_gb = archive_size / (1024 * 1024 * 1024)
        max_gb = settings.MAX_UPLOAD_SIZE_GB
        raise HTTPException(
            status_code=413,
            detail=f"Archive size ({size_gb:.2f} GB) exceeds maximum allowed size ({max_gb} GB)"
        )
    
    # Lưu file nén
    archive_path = settings.UPLOAD_FOLDER / archive.filename
    with open(archive_path, "wb") as f:
        f.write(content)
    
    try:
        # Giải nén
        extract_folder = settings.UPLOAD_FOLDER / f"extract_{batch_id}"
        extract_folder.mkdir(exist_ok=True)
        
        try:
            extracted_files = extract_archive(archive_path, extract_folder)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error extracting archive: {str(e)}")
        
        if not extracted_files:
            raise HTTPException(status_code=400, detail="No files found in archive")
        
        # Initialize batch job
        batch_jobs[batch_id] = {
            "status": "pending",
            "total_files": len(extracted_files),
            "processed": 0,
            "completed": 0,
            "failed": 0,
            "results": [],
            "errors": []
        }
        
        # Run batch scan in background
        if background_tasks:
            background_tasks.add_task(process_batch_scan, batch_id, extracted_files, batch_jobs)
        
        return BatchScanResponse(
            batch_id=batch_id,
            total_files=len(extracted_files),
            status="pending",
            processed=0,
            completed=0,
            failed=0
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing archive: {str(e)}")
    finally:
        # Dọn dẹp file nén sau khi xong
        if archive_path.exists():
            os.remove(archive_path)


@router.get("/batch/{batch_id}", response_model=BatchScanResult)
async def get_batch_result(batch_id: str):
    """Lấy kết quả batch scan"""
    if batch_id not in batch_jobs:
        raise HTTPException(status_code=404, detail="Batch job not found")
    
    job = batch_jobs[batch_id]
    return BatchScanResult(
        batch_id=batch_id,
        status=job["status"],
        total_files=job["total_files"],
        processed=job["processed"],
        completed=job["completed"],
        failed=job["failed"],
        results=job["results"],
        errors=job["errors"]
    )


@router.get("/batch/{batch_id}/status", response_model=BatchScanResponse)
async def get_batch_status(batch_id: str):
    """Lấy trạng thái batch scan"""
    if batch_id not in batch_jobs:
        raise HTTPException(status_code=404, detail="Batch job not found")
    
    job = batch_jobs[batch_id]
    return BatchScanResponse(
        batch_id=batch_id,
        total_files=job["total_files"],
        status=job["status"],
        processed=job["processed"],
        completed=job["completed"],
        failed=job["failed"]
    )

