# 📘 Hướng Dẫn Viết API - Backend Development

Tài liệu này giải thích **luồng viết một API endpoint mới** trong dự án Malware Detector.

## 🏗️ Kiến Trúc API

```
Request → Router → Service → Repository → Database
                ↓
            Response
```

## 📝 Luồng Viết API (Step-by-Step)

### **Bước 1: Tạo Schema (Data Validation)**

Tạo file schema trong `app/schemas/` để định nghĩa cấu trúc dữ liệu:

**File: `app/schemas/example.py`**

```python
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class ExampleRequest(BaseModel):
    """Request schema"""
    name: str
    description: Optional[str] = None
    tags: List[str] = []

class ExampleResponse(BaseModel):
    """Response schema"""
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True  # Cho phép convert từ ORM model
```

**Giải thích:**
- `BaseModel` từ Pydantic để validate data
- FastAPI tự động validate request/response
- `from_attributes = True` để convert từ database model

---

### **Bước 2: Tạo Service (Business Logic)**

Tạo service trong `app/services/` để xử lý logic:

**File: `app/services/example_service.py`**

```python
from typing import List, Optional
from app.database.analysis_repository import AnalysisRepository
from app.schemas.example import ExampleRequest, ExampleResponse

class ExampleService:
    """Service xử lý logic cho example"""
    
    def __init__(self):
        self.repo = AnalysisRepository()
    
    async def create_example(self, data: ExampleRequest) -> dict:
        """
        Tạo example mới
        
        Args:
            data: ExampleRequest schema
            
        Returns:
            dict: Dữ liệu đã tạo
        """
        # Xử lý business logic ở đây
        result = {
            "name": data.name,
            "description": data.description,
            "tags": data.tags
        }
        
        # Có thể gọi repository để lưu database
        # example_id = await self.repo.create(result)
        
        return result
    
    async def get_examples(self, limit: int = 100) -> List[dict]:
        """Lấy danh sách examples"""
        # Logic lấy dữ liệu
        return []
```

**Giải thích:**
- Service chứa **business logic**
- Không xử lý HTTP request/response
- Có thể gọi repository để truy cập database

---

### **Bước 3: Tạo Route (API Endpoint)**

Tạo route trong `app/api/v1/routes/`:

**File: `app/api/v1/routes/example.py`**

```python
"""
Example endpoints
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List
from app.schemas.example import ExampleRequest, ExampleResponse
from app.services.example_service import ExampleService

router = APIRouter()
example_service = ExampleService()

@router.post("", response_model=ExampleResponse)
async def create_example(data: ExampleRequest):
    """
    Tạo example mới
    
    - **name**: Tên example (required)
    - **description**: Mô tả (optional)
    - **tags**: Danh sách tags (optional)
    """
    try:
        result = await example_service.create_example(data)
        return ExampleResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("", response_model=List[ExampleResponse])
async def get_examples(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Lấy danh sách examples với pagination
    
    - **limit**: Số lượng kết quả (1-1000)
    - **offset**: Vị trí bắt đầu
    """
    try:
        results = await example_service.get_examples(limit=limit)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{example_id}", response_model=ExampleResponse)
async def get_example(example_id: int):
    """Lấy chi tiết example theo ID"""
    try:
        # Logic lấy example
        if example_id <= 0:
            raise HTTPException(status_code=404, detail="Example not found")
        
        return ExampleResponse(id=example_id, name="Example")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

**Giải thích:**
- `@router.post("")` - POST endpoint
- `@router.get("")` - GET endpoint
- `response_model` - Tự động validate response
- `Query()` - Query parameters với validation
- `HTTPException` - Xử lý lỗi

---

### **Bước 4: Đăng Ký Route**

Thêm route vào `app/api/v1/__init__.py`:

```python
from fastapi import APIRouter
from .routes import scan, health, websocket, analyses, example  # Thêm example

api_router = APIRouter()

# Include API routes
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
api_router.include_router(example.router, prefix="/example", tags=["example"])  # Thêm dòng này
```

**Giải thích:**
- `prefix="/example"` - URL prefix: `/api/example`
- `tags=["example"]` - Nhóm trong Swagger docs

---

### **Bước 5: Test API**

Sau khi chạy server, test API:

```bash
# Test POST
curl -X POST "http://localhost:5000/api/example" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "description": "Test description"}'

# Test GET
curl "http://localhost:5000/api/example?limit=10&offset=0"

# Test GET by ID
curl "http://localhost:5000/api/example/1"
```

Hoặc dùng Swagger UI: http://localhost:5000/api/docs

---

## 📊 Ví Dụ Thực Tế: API Scan File

Hãy xem API `/api/scan` hiện có để hiểu rõ hơn:

### **1. Schema: `app/schemas/scan.py`**

```python
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class ScanResult(BaseModel):
    filename: str
    sha256: Optional[str]
    md5: Optional[str]
    malware_detected: bool
    yara_matches: List[Dict[str, Any]]
    pe_info: Optional[Dict[str, Any]]
    suspicious_strings: List[str]
    capabilities: List[str]
    analysis_time: float
```

### **2. Service: `app/services/analyzer_service.py`**

```python
class AnalyzerService:
    async def analyze_and_save(self, filepath: str, filename: str):
        # Business logic: Phân tích file
        results = await self.analyze_single_file(filepath)
        static_analysis = self.analyze_with_static_analyzer(filepath)
        
        # Lưu vào database
        analysis_id = await self.analysis_repo.create(analysis_data)
        
        return analysis_data
```

### **3. Route: `app/api/v1/routes/scan.py`**

```python
@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    # 1. Lưu file upload
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)
    
    try:
        # 2. Gọi service để phân tích
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath),
            file.filename
        )
        
        # 3. Tạo response
        result = ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            malware_detected=analysis_data.get("malware_detected", False),
            ...
        )
        
        return result
    finally:
        # 4. Cleanup
        if filepath.exists():
            os.remove(filepath)
```

---

## 🔄 Luồng Xử Lý Request

```
1. Client gửi Request
   ↓
2. FastAPI nhận Request
   ↓
3. Router xử lý (app/api/v1/routes/*.py)
   - Validate request với Pydantic schema
   - Extract parameters (query, path, body)
   ↓
4. Gọi Service (app/services/*.py)
   - Xử lý business logic
   - Gọi Repository nếu cần database
   ↓
5. Repository (app/database/*.py)
   - Truy cập database
   - CRUD operations
   ↓
6. Service trả về kết quả
   ↓
7. Router tạo Response
   - Validate với response_model
   - Trả về JSON
   ↓
8. Client nhận Response
```

---

## 📋 Checklist Khi Viết API Mới

- [ ] **1. Tạo Schema** (`app/schemas/`)
  - Request schema (nếu có body)
  - Response schema
  
- [ ] **2. Tạo Service** (`app/services/`)
  - Business logic
  - Có thể gọi repository
  
- [ ] **3. Tạo Route** (`app/api/v1/routes/`)
  - Định nghĩa endpoint
  - Validate request/response
  - Xử lý lỗi
  
- [ ] **4. Đăng Ký Route** (`app/api/v1/__init__.py`)
  - Thêm vào api_router
  
- [ ] **5. Test API**
  - Dùng Swagger UI hoặc curl
  - Kiểm tra validation
  - Kiểm tra error handling

---

## 🎯 Best Practices

### **1. Validation**
- Luôn dùng Pydantic schemas
- Validate input và output
- Sử dụng `Query()`, `Path()` cho parameters

### **2. Error Handling**
```python
try:
    result = await service.do_something()
    return result
except ValueError as e:
    raise HTTPException(status_code=400, detail=str(e))
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))
```

### **3. Async/Await**
- Luôn dùng `async def` cho endpoints
- Dùng `await` khi gọi async functions

### **4. Documentation**
- Thêm docstring cho mỗi endpoint
- FastAPI tự động tạo Swagger docs

### **5. Separation of Concerns**
- **Route**: Chỉ xử lý HTTP
- **Service**: Business logic
- **Repository**: Database access

---

## 📚 Tài Liệu Tham Khảo

- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **Pydantic**: https://docs.pydantic.dev/
- **Swagger UI**: http://localhost:5000/api/docs (khi server chạy)

---

## 🎯 Tóm Tắt

**Luồng viết API:**
1. Schema → 2. Service → 3. Route → 4. Đăng ký → 5. Test

**Nguyên tắc:**
- Route chỉ xử lý HTTP
- Service chứa business logic
- Repository truy cập database
- Luôn validate với Pydantic

**Chúc bạn viết API thành công! 🚀**

