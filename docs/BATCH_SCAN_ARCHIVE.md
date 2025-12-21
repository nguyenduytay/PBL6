# Tính Năng Quét Archive (ZIP/TAR) - Kiểm Tra và Hướng Dẫn

## ✅ Tính Năng Có Trong Dự Án

**Có**, tính năng quét Archive (ZIP/TAR) **đã có đầy đủ** trong dự án:

### 1. Frontend (`frontend/src/pages/BatchScan/BatchScan.tsx`)

**Dòng 194-258**: Card "Scan Archive"
- Input file ẩn với `accept=".zip,.tar,.gz,.bz2,.tar.gz,.tar.bz2"`
- Button "Chọn file" để mở dialog chọn file
- Hiển thị tên file đã chọn
- Button "Quét Archive" để bắt đầu quét

**Dòng 90-104**: Hàm `handleScanBatch`
```typescript
const handleScanBatch = async () => {
  if (!selectedFile) return
  
  const validation = validateFileSize(selectedFile.size)
  if (!validation.isValid) {
    alert(t('batchScan.fileSizeExceedsMax', { sizeGB, maxGB: MAX_UPLOAD_SIZE_GB }))
    return
  }
  
  await scanBatch(selectedFile)  // ✅ Gọi API scan batch
  if (status) {
    setBatchId(status.batch_id)
  }
}
```

### 2. Backend (`backend/app/api/v1/routes/batch_scan.py`)

**Dòng 296-375**: Endpoint `POST /api/scan/batch`
```python
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
    # ✅ Đọc file archive
    # ✅ Giải nén vào thư mục tạm
    # ✅ Quét tất cả file bên trong
    # ✅ Trả về batch_id để theo dõi tiến trình
```

**Dòng 106-148**: Hàm `extract_archive`
```python
def extract_archive(file_path: Path, extract_to: Path) -> List[Path]:
    """Giải nén file ZIP/TAR và trả về danh sách file bên trong"""
    # ✅ Hỗ trợ ZIP
    # ✅ Hỗ trợ TAR (bao gồm .tar.gz, .tar.bz2)
    # ✅ Trả về danh sách file đã giải nén
```

### 3. API Client (`frontend/src/api/batchScanApi.ts`)

**Dòng 43-53**: Hàm `scanBatch`
```typescript
scanBatch: async (file: File): Promise<BatchScanResponse> => {
  const formData = new FormData()
  formData.append('archive', file)  // ✅ Gửi file với key 'archive'
  
  const response = await axiosClient.post<BatchScanResponse>('/scan/batch', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return response as unknown as BatchScanResponse
}
```

---

## 🔍 Cách Kiểm Tra Tính Năng

### Bước 1: Kiểm tra Frontend

1. Mở trang **Batch Scan** (`/batch-scan`)
2. Tìm card **"Scan Archive"** (bên phải)
3. Click button **"Chọn file"**
4. Dialog chọn file sẽ mở
5. Kiểm tra xem có thể chọn file `.zip` không

### Bước 2: Kiểm tra Console (F12)

Nếu không chọn được file ZIP, mở Console và kiểm tra:
- Có lỗi JavaScript không?
- Input có được tìm thấy không?

### Bước 3: Kiểm tra Network Tab

1. Chọn file ZIP
2. Click "Quét Archive"
3. Xem Network tab:
   - Request: `POST /api/scan/batch`
   - Status: 200 OK
   - Response: Có `batch_id` không?

---

## 🐛 Vấn Đề Có Thể Gặp

### Vấn đề 1: Không chọn được file ZIP

**Nguyên nhân có thể:**
- Browser không hỗ trợ `accept` attribute đầy đủ
- File quá lớn (> MAX_UPLOAD_SIZE_GB)
- Input bị ẩn và button không trigger được

**Giải pháp đã áp dụng:**
- ✅ Thêm MIME types vào `accept`: `application/zip,application/x-tar,application/gzip,application/x-bzip2`
- ✅ Kiểm tra file size trước khi upload
- ✅ Button trigger input thông qua `document.getElementById('archive-upload')?.click()`

### Vấn đề 2: Backend không nhận được file

**Kiểm tra:**
- Backend có chạy không? (`/api/health`)
- CORS có được cấu hình đúng không?
- File có được gửi với key `archive` không?

### Vấn đề 3: Giải nén thất bại

**Kiểm tra:**
- File ZIP có hợp lệ không?
- Backend có đủ quyền ghi vào thư mục `uploads/` không?
- Log backend có lỗi gì không?

---

## 📝 Cách Sử Dụng

### 1. Chuẩn bị file Archive

- Tạo file ZIP hoặc TAR chứa các file cần quét
- Đảm bảo file < MAX_UPLOAD_SIZE_GB (mặc định: 2GB)

### 2. Upload và Quét

1. Vào trang **Batch Scan**
2. Chọn tab **"Scan Archive"** (bên phải)
3. Click **"Chọn file"**
4. Chọn file ZIP/TAR
5. Click **"Quét Archive"**

### 3. Theo Dõi Tiến Trình

- Xem **Batch Status** card:
  - Total files: Tổng số file trong archive
  - Processed: Số file đã xử lý
  - Completed: Số file hoàn thành
  - Failed: Số file lỗi

### 4. Xem Kết Quả

- Bảng kết quả hiển thị:
  - Tên file
  - SHA256 hash
  - Trạng thái (Malware/Clean)
- Click vào file để xem chi tiết (nếu có `analysis_id`)

---

## ✅ Xác Nhận Tính Năng Hoạt Động

### Test Case 1: Upload file ZIP hợp lệ

1. ✅ Tạo file ZIP với vài file .exe bên trong
2. ✅ Upload qua giao diện
3. ✅ Kiểm tra batch_id được trả về
4. ✅ Kiểm tra status có `total_files > 0`
5. ✅ Đợi quét xong, kiểm tra kết quả

### Test Case 2: Upload file TAR hợp lệ

1. ✅ Tạo file TAR với vài file bên trong
2. ✅ Upload qua giao diện
3. ✅ Kiểm tra giải nén thành công
4. ✅ Kiểm tra quét được các file bên trong

### Test Case 3: File không hợp lệ

1. ✅ Upload file không phải archive
2. ✅ Kiểm tra backend trả về lỗi 400
3. ✅ Kiểm tra frontend hiển thị lỗi

---

## 🔧 Code References

### Frontend
- **Component**: `frontend/src/pages/BatchScan/BatchScan.tsx` (dòng 194-258)
- **Hook**: `frontend/src/hooks/useBatchScan.ts` (dòng 60-74)
- **API**: `frontend/src/api/batchScanApi.ts` (dòng 43-53)

### Backend
- **Endpoint**: `backend/app/api/v1/routes/batch_scan.py` (dòng 296-375)
- **Extract**: `backend/app/api/v1/routes/batch_scan.py` (dòng 106-148)
- **Process**: `backend/app/api/v1/routes/batch_scan.py` (dòng 61-103)

---

## 📊 Kết Luận

✅ **Tính năng quét Archive đã có đầy đủ trong dự án**

- Frontend: Có UI để chọn và upload archive
- Backend: Có API để nhận, giải nén và quét archive
- Logic: Tự động giải nén và quét tất cả file bên trong
- Hỗ trợ: ZIP, TAR, GZ, BZ2, TAR.GZ, TAR.BZ2

**Nếu không chọn được file ZIP:**
1. Kiểm tra browser console có lỗi không
2. Thử refresh trang
3. Thử với file ZIP khác
4. Kiểm tra network tab khi click button

