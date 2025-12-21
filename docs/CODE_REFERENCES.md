# Tham Chiếu Code: Upload Đơn Lẻ vs Batch Scan

## 📌 Tóm Tắt

- **Upload đơn lẻ**: Có thể chọn **YARA only**, **EMBER only**, hoặc **Full scan** (kết hợp cả 2)
- **Batch Scan**: **Luôn kết hợp cả YARA + EMBER** (không có tùy chọn)

---

## 1️⃣ Upload Đơn Lẻ - Có Thể Chọn

### Frontend: `frontend/src/pages/Upload/Upload.tsx`

**Dòng 14**: State để lưu loại scan được chọn
```typescript
const [scanType, setScanType] = useState<ScanType>('yara')
```

**Dòng 129-187**: Radio buttons để chọn loại scan
```typescript
{/* Scan Type Selection */}
<div className="mb-6">
  <label className="block text-sm font-medium text-gray-300 mb-3">
    {t('upload.scanType')}
  </label>
  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
    {/* YARA Option */}
    <div onClick={() => handleScanTypeChange('yara')}>
      <input type="radio" name="scanType" value="yara" />
      <label>{t('upload.scanTypeYara')}</label>
    </div>

    {/* EMBER Option */}
    <div onClick={() => handleScanTypeChange('ember')}>
      <input type="radio" name="scanType" value="ember" />
      <label>{t('upload.scanTypeEmber')}</label>
    </div>
  </div>
</div>
```

**Kết quả**: Người dùng có thể chọn `'yara'` hoặc `'ember'` trước khi upload.

---

### Backend: `backend/app/api/v1/routes/scan.py`

#### **Endpoint 1: Full Scan (Kết hợp cả 2)**
**Dòng 23-70**: `POST /api/scan`
```python
@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """
    API Upload & Scan File
    
    - Upload file lên server
    - Chạy toàn bộ các module: Hash, YARA, EMBER
    - Trả về kết quả phân tích
    """
    # ...
    # Phân tích file (Hash + YARA + EMBER) và lưu vào database
    analysis_data = await analyzer_service.analyze_and_save(
        str(filepath),
        file.filename
        # ⚠️ KHÔNG truyền scan_modules → Dùng default = ["hash", "yara", "ember"]
    )
```

**Kết quả**: Chạy **cả YARA và EMBER** (full scan).

---

#### **Endpoint 2: YARA Only**
**Dòng 72-109**: `POST /api/scan/yara`
```python
@router.post("/yara", response_model=ScanResult)
async def scan_yara(file: UploadFile = File(...)):
    """
    API Quét YARA (Nhanh)
    
    - Chỉ sử dụng luật YARA để phát hiện malware
    - Phù hợp phân tích nhanh theo signatures
    """
    # ...
    # Chỉ quét bằng YARA (không chạy Hash hay EMBER)
    analysis_data = await analyzer_service.analyze_and_save(
        str(filepath), 
        file.filename, 
        scan_modules=["yara"]  # ✅ CHỈ YARA
    )
```

**Kết quả**: Chỉ chạy **YARA**, không chạy EMBER.

---

#### **Endpoint 3: EMBER Only**
**Dòng 111-177**: `POST /api/scan/ember`
```python
@router.post("/ember", response_model=ScanResult)
async def scan_ember(file: UploadFile = File(...)):
    """
    API Quét EMBER AI (Chuyên sâu)
    
    - Sử dụng Machine Learning để phát hiện mẫu lạ
    - Chỉ chạy EMBER model, không chạy YARA hoặc hash check
    """
    # ...
    # Chỉ quét bằng EMBER AI (không chạy Hash hay YARA)
    analysis_data = await analyzer_service.analyze_and_save(
        str(filepath), 
        file.filename, 
        scan_modules=["ember"]  # ✅ CHỈ EMBER
    )
```

**Kết quả**: Chỉ chạy **EMBER**, không chạy YARA.

---

### Service: `backend/app/services/analyzer_service.py`

**Dòng 36-48**: Logic xử lý `scan_modules`
```python
async def analyze_single_file(self, filepath: str, scan_modules: List[str] = None) -> List[Dict[str, Any]]:
    """
    Phân tích một file đơn lẻ
    
    Args:
        filepath: Đường dẫn file
        scan_modules: List các modules chạy ["yara", "ember", "hash"]. 
                      Default None = Run All.
    """
    if scan_modules is None:
        scan_modules = ["hash", "yara", "ember"]  # ✅ Default: Cả 3
    
    # ...
    # 2) Quét YARA - phát hiện malware dựa trên patterns
    if "yara" in scan_modules:  # ✅ Chỉ chạy nếu có trong list
        yara_results = self.yara_service.scan_file(filepath)
        results.extend(yara_results)

    # 3) Phân tích EMBER - sử dụng machine learning
    if "ember" in scan_modules:  # ✅ Chỉ chạy nếu có trong list
        ember_result = self.ember_model.predict(filepath)
        # ...
```

**Kết quả**: 
- Nếu `scan_modules=None` → Chạy cả YARA và EMBER
- Nếu `scan_modules=["yara"]` → Chỉ chạy YARA
- Nếu `scan_modules=["ember"]` → Chỉ chạy EMBER

---

## 2️⃣ Batch Scan - Luôn Kết Hợp Cả 2

### Backend: `backend/app/api/v1/routes/batch_scan.py`

**Dòng 61-103**: Hàm xử lý batch scan
```python
async def process_batch_scan(batch_id: str, files: List[Path], batch_jobs: dict):
    """Xử lý quét hàng loạt trong background task"""
    # ...
    # Quét từng file trong danh sách
    for file_path in files:
        try:
            batch_jobs[batch_id]["processed"] += 1
            
            # Phân tích file và lưu vào database
            analysis_data = await analyzer_service.analyze_and_save(
                str(file_path),
                file_path.name
                # ⚠️ KHÔNG truyền scan_modules → Dùng default = ["hash", "yara", "ember"]
            )
            
            # Ghi lại kết quả thành công
            batch_jobs[batch_id]["completed"] += 1
            # ...
```

**Điểm quan trọng**: 
- **KHÔNG truyền `scan_modules`** → Dùng default = `["hash", "yara", "ember"]`
- **Luôn chạy cả YARA và EMBER** cho mỗi file trong batch

---

### Các Endpoint Batch Scan

#### **Endpoint 1: Scan Folder**
**Dòng 212-291**: `POST /api/scan/folder-upload`
```python
@router.post("/folder-upload", response_model=BatchScanResponse)
async def scan_folder_upload(
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = None
):
    # ...
    # Chạy batch scan trong background
    background_tasks.add_task(process_batch_scan, batch_id, files_to_scan, batch_jobs)
    # ⚠️ Gọi process_batch_scan() → Luôn dùng default scan_modules
```

#### **Endpoint 2: Scan Archive**
**Dòng 296-375**: `POST /api/scan/batch`
```python
@router.post("/batch", response_model=BatchScanResponse)
async def scan_batch(
    archive: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    # ...
    # Run batch scan in background
    if background_tasks:
        background_tasks.add_task(process_batch_scan, batch_id, extracted_files, batch_jobs)
    # ⚠️ Gọi process_batch_scan() → Luôn dùng default scan_modules
```

**Kết quả**: Cả 2 endpoint đều gọi `process_batch_scan()` → **Luôn kết hợp YARA + EMBER**.

---

## 📊 So Sánh

| Tính năng | Upload Đơn Lẻ | Batch Scan |
|-----------|---------------|------------|
| **Có thể chọn loại scan?** | ✅ Có (YARA/EMBER/Full) | ❌ Không |
| **YARA only** | ✅ Có (`/api/scan/yara`) | ❌ Không |
| **EMBER only** | ✅ Có (`/api/scan/ember`) | ❌ Không |
| **Full scan (cả 2)** | ✅ Có (`/api/scan`) | ✅ Luôn dùng |
| **Tham số `scan_modules`** | ✅ Có thể truyền | ❌ Không truyền (dùng default) |
| **Default behavior** | `["hash", "yara", "ember"]` | `["hash", "yara", "ember"]` |

---

## 🔍 Cách Kiểm Tra Trong Code

### Để biết Upload đơn lẻ có thể chọn:
1. Xem `frontend/src/pages/Upload/Upload.tsx` → Có radio buttons chọn scan type
2. Xem `backend/app/api/v1/routes/scan.py` → Có 3 endpoints riêng biệt:
   - `POST /api/scan` (full)
   - `POST /api/scan/yara` (yara only)
   - `POST /api/scan/ember` (ember only)

### Để biết Batch Scan luôn kết hợp cả 2:
1. Xem `backend/app/api/v1/routes/batch_scan.py` → Hàm `process_batch_scan()`
2. Kiểm tra dòng 80-83: Gọi `analyze_and_save()` **KHÔNG truyền `scan_modules`**
3. Xem `analyzer_service.py` dòng 47-48: Default = `["hash", "yara", "ember"]`

---

## ✅ Kết Luận

- **Upload đơn lẻ**: Có 3 lựa chọn (YARA only, EMBER only, Full scan)
- **Batch Scan**: Chỉ có 1 lựa chọn (Full scan - luôn kết hợp YARA + EMBER)

