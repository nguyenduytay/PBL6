# Kiểm Tra File và Xử Lý Lỗi - Hướng Dẫn Chi Tiết

## Mục Lục

1. [Tổng Quan Quy Trình Kiểm Tra](#tổng-quan-quy-trình-kiểm-tra)
2. [Bước 1: Kiểm Tra File Upload](#bước-1-kiểm-tra-file-upload)
3. [Bước 2: Kiểm Tra Định Dạng File](#bước-2-kiểm-tra-định-dạng-file)
4. [Bước 3: Kiểm Tra Trong Quá Trình Phân Tích](#bước-3-kiểm-tra-trong-quá-trình-phân-tích)
5. [Bước 4: Xử Lý Lỗi](#bước-4-xử-lý-lỗi)
6. [Các Loại Lỗi Thường Gặp](#các-loại-lỗi-thường-gặp)
7. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

---

## Tổng Quan Quy Trình Kiểm Tra

Hệ thống thực hiện kiểm tra file qua **4 giai đoạn chính**:

```
1. Upload File
   ↓
   [Kiểm tra tên file, kích thước]
   ↓
2. Validate Format
   ↓
   [Kiểm tra định dạng PE, header, cấu trúc]
   ↓
3. Phân Tích
   ↓
   [Kiểm tra lỗi trong quá trình phân tích]
   ↓
4. Xử Lý Lỗi
   ↓
   [Báo lỗi, log, trả response]
```

---

## Bước 1: Kiểm Tra File Upload

### 1.1. Kiểm Tra Tên File

**File**: `backend/app/api/v1/routes/scan.py`

```python
@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    # 1.1.1. Kiểm tra file có tên không
    if not file.filename:
        # Nếu không có tên file → Báo lỗi ngay
        raise HTTPException(
            status_code=400, 
            detail="Filename is required"
        )
    
    # 1.1.2. File hợp lệ → Tiếp tục xử lý
    filepath = settings.UPLOAD_FOLDER / file.filename
```

**Giải thích**:
- **Mục đích**: Đảm bảo file có tên để lưu vào disk
- **Lỗi**: Nếu `file.filename` là `None` hoặc rỗng
- **Xử lý**: Trả về HTTP 400 (Bad Request) với thông báo lỗi

**Ví dụ lỗi**:
```json
{
  "detail": "Filename is required"
}
```

### 1.2. Kiểm Tra Kích Thước File

**File**: `frontend/src/pages/Upload/Upload.tsx`

```typescript
// Frontend kiểm tra trước khi upload
const MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB
const MAX_UPLOAD_SIZE_GB = 100;

if (file.size > MAX_UPLOAD_SIZE_BYTES) {
  alert(`File quá lớn! Kích thước tối đa: ${MAX_UPLOAD_SIZE_GB} GB`);
  return; // Không upload
}
```

**Giải thích**:
- **Mục đích**: Tránh upload file quá lớn làm tốn tài nguyên server
- **Giới hạn**: 100 MB (có thể điều chỉnh)
- **Xử lý**: Frontend chặn trước khi gửi request

### 1.3. Lưu File Tạm

```python
# 1.3.1. Tạo đường dẫn file tạm
filepath = settings.UPLOAD_FOLDER / file.filename
# Ví dụ: uploads/malware.exe

# 1.3.2. Đọc nội dung file từ request
content = await file.read()

# 1.3.3. Ghi file vào disk
with open(filepath, "wb") as f:
    f.write(content)
```

**Giải thích**:
- **Mục đích**: Lưu file tạm để phân tích
- **Vị trí**: `backend/uploads/` (hoặc `/app/uploads/` trong Docker)
- **Lưu ý**: File sẽ được xóa sau khi phân tích xong (trong `finally` block)

**Xử lý lỗi**:
```python
try:
    # Phân tích file
    analysis_data = await analyzer_service.analyze_and_save(...)
except Exception as e:
    # Nếu có lỗi → Báo lỗi
    raise HTTPException(
        status_code=500, 
        detail=f"Analysis error: {str(e)}"
    )
finally:
    # Luôn xóa file tạm, dù có lỗi hay không
    if filepath.exists():
        os.remove(filepath)
```

---

## Bước 2: Kiểm Tra Định Dạng File

### 2.1. Kiểm Tra File PE (Cho EMBER)

**File**: `backend/app/api/v1/routes/scan.py` (endpoint `/scan/ember`)

```python
@router.post("/ember", response_model=ScanResult)
async def scan_ember(file: UploadFile = File(...)):
    # 2.1.1. Kiểm tra file có phải PE không
    from app.ml.ember_model import EmberModel
    ember_model = EmberModel()
    is_pe, pe_error_detail = ember_model.is_pe_file(str(filepath))
    
    # 2.1.2. Nếu không phải PE → Báo lỗi
    if not is_pe:
        error_detail = "File is not a valid PE file. EMBER only analyzes PE files..."
        if pe_error_detail:
            error_detail += f" Details: {pe_error_detail}"
        raise HTTPException(
            status_code=400, 
            detail=error_detail
        )
```

**Giải thích**:
- **Mục đích**: EMBER chỉ phân tích file PE (.exe, .dll, .sys, .scr)
- **Kiểm tra**: File phải có header "MZ" và cấu trúc PE hợp lệ
- **Lỗi**: Nếu không phải PE → Trả về HTTP 400

### 2.2. Chi Tiết Kiểm Tra PE File

**File**: `backend/app/ml/ember_model.py`

```python
def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
    """Kiểm tra file có phải PE file không"""
    try:
        # 2.2.1. Kiểm tra file tồn tại
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return False, f"File does not exist: {file_path}"
        
        # 2.2.2. Kiểm tra kích thước file (tối thiểu 64 bytes)
        file_size = file_path_obj.stat().st_size
        if file_size < 64:
            return False, f"File too small ({file_size} bytes). PE files must be at least 64 bytes"
        
        # 2.2.3. Kiểm tra MZ header (2 bytes đầu)
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header != b'MZ':
                header_hex = header.hex().upper() if len(header) == 2 else "N/A"
                return False, f"Invalid PE header. Expected 'MZ', got: {header_hex}"
            
            # 2.2.4. Kiểm tra PE signature (ở offset 0x3C)
            f.seek(0x3C)  # Đọc offset đến PE header
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) == 4:
                pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
                
                # Kiểm tra offset hợp lệ
                if pe_offset < file_size and pe_offset > 0:
                    f.seek(pe_offset)
                    pe_signature = f.read(2)
                    if pe_signature == b'PE':
                        return True, None  # File PE hợp lệ
                    else:
                        return False, f"Invalid PE signature at offset {pe_offset}. Expected 'PE', got: {pe_signature.hex().upper()}"
        
        return True, None  # Có MZ header → Coi là PE
        
    except PermissionError as e:
        return False, f"Permission denied: {str(e)}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"
```

**Các Trường Hợp Kiểm Tra**:

1. **File không tồn tại**:
   ```python
   return False, "File does not exist: /path/to/file.exe"
   ```

2. **File quá nhỏ** (< 64 bytes):
   ```python
   return False, "File too small (32 bytes). PE files must be at least 64 bytes"
   ```

3. **Không có MZ header**:
   ```python
   return False, "Invalid PE header. Expected 'MZ', got: 4D5A"
   ```

4. **Không có PE signature**:
   ```python
   return False, "Invalid PE signature at offset 120. Expected 'PE', got: 0000"
   ```

5. **Lỗi quyền truy cập**:
   ```python
   return False, "Permission denied: [Errno 13] Permission denied"
   ```

**Ví dụ Response Lỗi**:
```json
{
  "detail": "File is not a valid PE file. EMBER only analyzes PE files (Portable Executable: .exe, .dll, .sys, .scr, etc.). PE files must start with 'MZ' header. Details: Invalid PE header. Expected 'MZ', got: 504B"
}
```

---

## Bước 3: Kiểm Tra Trong Quá Trình Phân Tích

### 3.1. Kiểm Tra Model Đã Load

**File**: `backend/app/ml/ember_model.py`

```python
def predict(self, file_path: str) -> Dict[str, Any]:
    # 3.1.1. Kiểm tra model đã load chưa
    if not self.model:
        return {
            "error": "Model not loaded", 
            "is_malware": False, 
            "score": 0.0,
            "model_name": self.model_filename
        }
```

**Giải thích**:
- **Mục đích**: Đảm bảo EMBER model đã được load trước khi predict
- **Lỗi**: Nếu model = None (không load được)
- **Xử lý**: Trả về error message, không crash

### 3.2. Kiểm Tra Feature Extraction

```python
# 3.2.1. Extract features
features = self.extractor.feature_vector(bytez)

# 3.2.2. Kiểm tra features có rỗng không
if features is None or len(features) == 0:
    return {
        "error": "Feature extraction returned empty vector",
        "is_malware": False,
        "score": 0.0
    }

# 3.2.3. Kiểm tra features có toàn số 0 không (có thể do lỗi)
if np.all(features == 0):
    return {
        "error": "Feature vector contains only zeros - extraction likely failed",
        "is_malware": False,
        "score": 0.0
    }
```

**Giải thích**:
- **Mục đích**: Đảm bảo feature extraction thành công
- **Lỗi**: Features rỗng hoặc toàn số 0 → Có thể do file không hợp lệ
- **Xử lý**: Trả về error, không predict

### 3.3. Kiểm Tra Score = 0.0

```python
# 3.3.1. Predict
score = ember.predict_sample(self.model, bytez, feature_version=2)
score = float(score)

# 3.3.2. Kiểm tra score = 0.0 có phải do lỗi không
if score == 0.0:
    test_features = self.extractor.feature_vector(bytez)
    if np.all(test_features == 0):
        return {
            "error": "Score is 0.0 and feature vector is all zeros - extraction likely failed",
            "is_malware": False,
            "score": 0.0
        }
```

**Giải thích**:
- **Mục đích**: Phân biệt score = 0.0 do file sạch vs do lỗi extraction
- **Kiểm tra**: Nếu features toàn số 0 → Lỗi extraction
- **Xử lý**: Trả về error thay vì coi là file sạch

### 3.4. Kiểm Tra File Tồn Tại (Static Analyzer)

**File**: `backend/app/services/static_analyzer_impl.py`

```python
def analyze_file(self, filepath: str) -> Dict[str, Any]:
    # 3.4.1. Kiểm tra file tồn tại
    filepath_obj = Path(filepath)
    if not filepath_obj.exists():
        # Trả về kết quả rỗng thay vì crash
        return self._empty_result()
    
    try:
        # Đọc file
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Phân tích...
        
    except Exception as e:
        # 3.4.2. Xử lý lỗi khi đọc file
        print(f"[StaticAnalyzer] Error analyzing {filepath}: {e}")
        import traceback
        traceback.print_exc()
        return self._empty_result()  # Trả về kết quả rỗng
```

**Giải thích**:
- **Mục đích**: Tránh crash khi file không tồn tại hoặc lỗi đọc
- **Xử lý**: Trả về `_empty_result()` (tất cả fields = None hoặc [])
- **Lưu ý**: Log lỗi để debug, nhưng không throw exception

### 3.5. Kiểm Tra PE Parsing

```python
# 3.5.1. Thử parse PE file
try:
    pe_info = self._analyze_pe_file(filepath, file_content)
    if pe_info:
        result["pe_info"] = pe_info
        result["capabilities"] = self._extract_capabilities(pe_info)
except Exception as e:
    # 3.5.2. Nếu không phải PE hoặc lỗi parse → Bỏ qua
    print(f"[StaticAnalyzer] Not a PE file or error parsing: {e}")
    # Không throw exception → Tiếp tục xử lý các phần khác
```

**Giải thích**:
- **Mục đích**: Cho phép phân tích file không phải PE (chỉ bỏ qua PE info)
- **Xử lý**: Catch exception, log, tiếp tục extract strings và hashes
- **Kết quả**: `pe_info = None`, nhưng vẫn có `strings` và `hashes`

---

## Bước 4: Xử Lý Lỗi

### 4.1. Phân Loại Lỗi

Hệ thống phân loại lỗi thành **3 loại chính**:

#### 4.1.1. Lỗi Validation (HTTP 400)

**Ví dụ**:
- File không có tên
- File không phải PE (cho EMBER scan)
- File quá lớn

**Xử lý**:
```python
raise HTTPException(
    status_code=400, 
    detail="Error message"
)
```

**Response**:
```json
{
  "detail": "Filename is required"
}
```

#### 4.1.2. Lỗi Phân Tích (HTTP 500)

**Ví dụ**:
- Model không load được
- Feature extraction failed
- Database connection error

**Xử lý**:
```python
try:
    # Phân tích
    analysis_data = await analyzer_service.analyze_and_save(...)
except Exception as e:
    raise HTTPException(
        status_code=500, 
        detail=f"Analysis error: {str(e)}"
    )
```

**Response**:
```json
{
  "detail": "Analysis error: Model not loaded"
}
```

#### 4.1.3. Lỗi Nhẹ (Trả Về Trong Results)

**Ví dụ**:
- EMBER error (file không phải PE)
- YARA error (rules không load)
- Static analyzer error (file không parse được)

**Xử lý**:
```python
# Không throw exception
# Trả về error trong results
results.append({
    "type": "ember_error",
    "message": "[ERROR] EMBER prediction failed: ...",
    "score": 0.0
})
```

**Response**:
```json
{
  "results": [
    {
      "type": "ember_error",
      "message": "[ERROR] EMBER prediction failed: File is not a valid PE file",
      "score": 0.0
    }
  ]
}
```

### 4.2. Error Handling trong EMBER

**File**: `backend/app/ml/ember_model.py`

```python
def predict(self, file_path: str) -> Dict[str, Any]:
    try:
        # Predict...
        return {
            "score": float(score),
            "is_malware": score > self.threshold
        }
    except Exception as e:
        error_type = type(e).__name__  # "ValueError", "ImportError", etc.
        error_message = str(e)
        
        # 4.2.1. Phân loại lỗi theo nội dung
        if "lief" in error_message.lower() or "bad_format" in error_message.lower():
            error_detail = f"LIEF parsing error: {error_message}"
        elif "numpy" in error_message.lower() or "shape" in error_message.lower():
            error_detail = f"Feature extraction error: {error_message}"
        elif "lightgbm" in error_message.lower() or "model" in error_message.lower():
            error_detail = f"Model prediction error: {error_message}"
        else:
            error_detail = error_message
        
        # 4.2.2. Log lỗi
        print(f"[ERROR] EMBER prediction failed: {error_detail}")
        
        # 4.2.3. Trả về error (không throw exception)
        return {
            "error": error_detail,
            "error_type": error_type,
            "is_malware": False, 
            "score": 0.0
        }
```

**Giải thích**:
- **Mục đích**: Phân loại lỗi để dễ debug
- **Xử lý**: Log lỗi, trả về error message trong response
- **Lưu ý**: Không throw exception → Không crash hệ thống

### 4.3. Error Handling trong YARA

**File**: `backend/app/services/yara_service.py`

```python
def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
    try:
        matches = self.rules.match(filepath)
        # Xử lý matches...
        return results
    except Exception as e:
        # 4.3.1. Log lỗi chi tiết
        print(f"[YARA] ERROR scanning {filepath}: {e}")
        import traceback
        traceback.print_exc()
        
        # 4.3.2. Trả về error result
        return [{
            "type": "yara_error",
            "message": f"Lỗi quét YARA: {str(e)}",
            "infoUrl": None
        }]
```

**Giải thích**:
- **Mục đích**: Xử lý lỗi khi YARA scan fail
- **Xử lý**: Log traceback, trả về error result
- **Lưu ý**: Không throw exception → Tiếp tục các module khác

### 4.4. Error Handling trong Database

**File**: `backend/app/services/analysis_service.py`

```python
async def create(analysis_data: Dict[str, Any]) -> Optional[int]:
    try:
        # Insert vào database...
        analysis_id = cursor.lastrowid
        return analysis_id
    except Exception as e:
        # 4.4.1. Log lỗi chi tiết
        logger.error(f"Exception while saving analysis: {e}", exc_info=True)
        # 4.4.2. Trả về None (không throw exception)
        return None
```

**Xử lý trong AnalyzerService**:

```python
try:
    analysis_id = await self.analysis_service.create(analysis_data)
    if analysis_id:
        analysis_data['id'] = analysis_id
        return analysis_data
    else:
        # 4.4.3. Nếu không lưu được → Vẫn trả về kết quả
        logger.warning(f"Failed to save analysis - analysis_id is None")
        analysis_data['results'] = results
        return analysis_data
except Exception as e:
    # 4.4.4. Lỗi khác → Vẫn trả về kết quả
    logger.error(f"Exception while saving: {e}", exc_info=True)
    analysis_data['results'] = results
    return analysis_data
```

**Giải thích**:
- **Mục đích**: Đảm bảo kết quả phân tích vẫn được trả về dù database lỗi
- **Xử lý**: Log lỗi, trả về kết quả (không có `id`)
- **Lưu ý**: User vẫn nhận được kết quả phân tích, chỉ không lưu vào database

---

## Các Loại Lỗi Thường Gặp

### 5.1. Lỗi File Upload

#### 5.1.1. File Không Có Tên

**Nguyên nhân**: Frontend gửi file không có `filename`

**Lỗi**:
```json
{
  "detail": "Filename is required"
}
```

**Cách xử lý**: Đảm bảo file có tên trước khi upload

#### 5.1.2. File Quá Lớn

**Nguyên nhân**: File vượt quá giới hạn (100 MB)

**Lỗi**: Frontend chặn trước khi upload

**Cách xử lý**: Giảm kích thước file hoặc tăng `MAX_UPLOAD_SIZE_BYTES`

### 5.2. Lỗi Định Dạng File

#### 5.2.1. File Không Phải PE (Cho EMBER)

**Nguyên nhân**: Upload file không phải PE (.txt, .pdf, .jpg, etc.)

**Lỗi**:
```json
{
  "detail": "File is not a valid PE file. EMBER only analyzes PE files..."
}
```

**Cách xử lý**: 
- Sử dụng `/scan` (full scan) thay vì `/scan/ember`
- Hoặc upload file PE (.exe, .dll, .sys)

#### 5.2.2. File PE Bị Hỏng

**Nguyên nhân**: File có MZ header nhưng cấu trúc PE không hợp lệ

**Lỗi**:
```json
{
  "detail": "Invalid PE signature at offset 120. Expected 'PE', got: 0000"
}
```

**Cách xử lý**: File bị corrupt, cần file PE hợp lệ

### 5.3. Lỗi Model EMBER

#### 5.3.1. Model Không Load Được

**Nguyên nhân**: File model không tồn tại hoặc bị hỏng

**Lỗi**:
```json
{
  "type": "ember_error",
  "message": "[ERROR] EMBER prediction failed: Model not loaded",
  "score": 0.0
}
```

**Cách xử lý**: 
- Kiểm tra file `ember_model_2018.txt` có tồn tại không
- Kiểm tra đường dẫn model trong `EmberModel._find_model_path()`

#### 5.3.2. Feature Extraction Failed

**Nguyên nhân**: File không parse được hoặc ember library lỗi

**Lỗi**:
```json
{
  "type": "ember_error",
  "message": "[ERROR] EMBER prediction failed: Feature extraction error: ...",
  "score": 0.0
}
```

**Cách xử lý**: 
- Kiểm tra ember library đã cài đặt chưa
- Kiểm tra file có phải PE hợp lệ không

### 5.4. Lỗi YARA

#### 5.4.1. YARA Rules Không Load

**Nguyên nhân**: File rules không tồn tại hoặc bị hỏng

**Lỗi**:
```json
{
  "type": "yara_error",
  "message": "Lỗi quét YARA: ..."
}
```

**Cách xử lý**: 
- Kiểm tra file `yara_rules/rules/index.yar`
- Kiểm tra YARA service đã khởi tạo chưa

### 5.5. Lỗi Database

#### 5.5.1. Connection Error

**Nguyên nhân**: MySQL không chạy hoặc connection string sai

**Lỗi**: Log trong server, nhưng vẫn trả về kết quả phân tích

**Cách xử lý**: 
- Kiểm tra MySQL đang chạy
- Kiểm tra connection string trong `.env`

#### 5.5.2. Insert Error

**Nguyên nhân**: Schema không đúng hoặc constraint violation

**Lỗi**: Log trong server, nhưng vẫn trả về kết quả phân tích

**Cách xử lý**: 
- Kiểm tra database schema
- Kiểm tra dữ liệu có hợp lệ không

---

## Ví Dụ Thực Tế

### Ví Dụ 1: File Không Phải PE

**Request**:
```bash
POST /api/v1/scan/ember
Content-Type: multipart/form-data

file: document.pdf
```

**Response** (HTTP 400):
```json
{
  "detail": "File is not a valid PE file. EMBER only analyzes PE files (Portable Executable: .exe, .dll, .sys, .scr, etc.). PE files must start with 'MZ' header. Details: Invalid PE header. Expected 'MZ', got: 255044"
}
```

**Giải thích**:
- File PDF có header `%PDF` (hex: `255044`)
- EMBER chỉ chấp nhận file PE (header `MZ`)
- Hệ thống báo lỗi ngay khi kiểm tra

### Ví Dụ 2: EMBER Model Lỗi

**Request**:
```bash
POST /api/v1/scan/ember
file: malware.exe
```

**Response** (HTTP 200, nhưng có error trong results):
```json
{
  "filename": "malware.exe",
  "results": [
    {
      "type": "ember_error",
      "message": "[ERROR] EMBER prediction failed: Model not loaded",
      "score": 0.0,
      "error_type": "AttributeError"
    }
  ],
  "malware_detected": false
}
```

**Giải thích**:
- Model không load được (có thể do file model không tồn tại)
- Hệ thống vẫn trả về response, nhưng có error trong `results`
- `malware_detected = false` (vì không có detection nào)

### Ví Dụ 3: YARA Error

**Request**:
```bash
POST /api/v1/scan
file: malware.exe
```

**Response** (HTTP 200, có error trong results):
```json
{
  "filename": "malware.exe",
  "results": [
    {
      "type": "yara_error",
      "message": "Lỗi quét YARA: YARA rules not loaded",
      "infoUrl": null
    },
    {
      "type": "model",
      "subtype": "ember",
      "score": 0.9234,
      "threshold": 0.8336
    }
  ],
  "malware_detected": true
}
```

**Giải thích**:
- YARA lỗi (rules không load)
- EMBER vẫn chạy và phát hiện malware (score = 0.9234 > threshold)
- `malware_detected = true` (vì có EMBER detection)

### Ví Dụ 4: Database Error

**Request**:
```bash
POST /api/v1/scan
file: malware.exe
```

**Response** (HTTP 200, nhưng không có `id`):
```json
{
  "filename": "malware.exe",
  "sha256": "80b4182a...",
  "malware_detected": true,
  "results": [...]
  // Không có "id" vì database lỗi
}
```

**Server Log**:
```
[ERROR] Exception while saving analysis: (2006, "MySQL server has gone away")
```

**Giải thích**:
- Database connection bị mất
- Phân tích vẫn thành công
- Kết quả vẫn được trả về, nhưng không lưu vào database

---

## Tóm Tắt

### Quy Trình Kiểm Tra

1. **Upload**: Kiểm tra tên file, kích thước
2. **Format**: Kiểm tra định dạng PE (cho EMBER)
3. **Analysis**: Kiểm tra model, features, parsing
4. **Error Handling**: Phân loại và xử lý lỗi

### Nguyên Tắc Xử Lý Lỗi

1. **Validation errors** → HTTP 400 (Bad Request)
2. **Analysis errors** → HTTP 500 (Internal Server Error)
3. **Module errors** → Trả về trong `results` (không crash)
4. **Database errors** → Log, nhưng vẫn trả về kết quả

### Lưu Ý

- **Luôn xóa file tạm** trong `finally` block
- **Không throw exception** trong module analysis (trả về error trong results)
- **Log chi tiết** để debug
- **Trả về kết quả** dù có lỗi (trừ validation errors)

---

**Tài liệu này giải thích chi tiết cách hệ thống kiểm tra file và xử lý lỗi trong quá trình phân tích malware.**

