# ⚡ Hướng Dẫn Bắt Đầu Nhanh

Hướng dẫn nhanh để chạy dự án Malware Detector trong 5 phút.

## 🎯 Dự Án Là Gì?

**Malware Detector** là hệ thống phát hiện mã độc sử dụng:

- ✅ **YARA Rules** - Pattern matching để phát hiện malware
- ✅ **Hash Detection** - So sánh hash với database đã biết
- ✅ **Static Analysis** - Phân tích PE files, strings, capabilities

## 🚀 Chạy Dự Án (4 Bước)

### **Bước 1: Tạo và Kích Hoạt Virtual Environment**

```bash
# Tạo venv (nếu chưa có)
python -m venv venv

# Kích hoạt venv
.\venv\Scripts\Activate.ps1  # Windows PowerShell
# hoặc
venv\Scripts\activate.bat     # Windows CMD
# hoặc
source venv/bin/activate      # Linux/Mac
```

**Kiểm tra**: Bạn sẽ thấy `(venv)` ở đầu dòng prompt.

### **Bước 2: Cài Đặt Dependencies**

```bash
# Đảm bảo venv đã kích hoạt (sẽ thấy (venv) ở đầu)
pip install -r config/requirements.txt
```

### **Bước 3: Chạy Ứng Dụng**

```bash
# Chạy với uvicorn (khuyến nghị)
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 5000

# HOẶC chạy trực tiếp
python -m app.main
```

### **Bước 4: Truy Cập**

Mở trình duyệt và truy cập:

- ✅ **Web UI**: http://localhost:5000
- ✅ **API Docs (Swagger)**: http://localhost:5000/api/docs
- ✅ **ReDoc**: http://localhost:5000/api/redoc
- ✅ **Health Check**: http://localhost:5000/api/health

**⚠️ Lưu ý**: Dùng `http://localhost:5000` hoặc `http://127.0.0.1:5000`, không dùng `http://0.0.0.0:5000`

## 📝 Sử Dụng

### **1. Upload File Qua Web UI**

1. Mở http://localhost:5000
2. Click "Submit File"
3. Chọn file cần phân tích
4. Xem kết quả

### **2. Sử Dụng API**

```bash
# Quét file
curl -X POST "http://localhost:5000/api/scan" \
  -F "file=@test.exe"

# Xem lịch sử (nếu có database)
curl "http://localhost:5000/api/analyses"
```

## ⚙️ Cấu Hình (Optional)

### **Database (Để lưu lịch sử)**

1. Tạo file `.env` trong root:

```env
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_NAME=malwaredetection
DB_PORT=3306
```

2. Tạo database:

```sql
CREATE DATABASE malwaredetection;
```

3. Restart ứng dụng - tables sẽ tự động tạo

## 🛑 Dừng Ứng Dụng

Nhấn `Ctrl + C` trong terminal để dừng server.

Để tắt venv:

```bash
deactivate
```

## ❓ Gặp Vấn Đề?

### **Lỗi ModuleNotFoundError**

- Đảm bảo đã kích hoạt venv (`(venv)` ở đầu prompt)
- Kiểm tra: `pip list` để xem packages đã cài chưa

### **Lỗi PyYAML trên Windows (AttributeError: cython_sources)**

**Nguyên nhân**: PyYAML cần compile từ source nhưng thiếu build tools.

**Giải pháp 1: Cài đặt pre-built wheel (Khuyến nghị)**

```bash
# Cập nhật pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Cài PyYAML với pre-built wheel
pip install --only-binary :all: PyYAML

# Sau đó cài các packages còn lại
pip install -r requirements.txt
```

**Giải pháp 2: Cài Microsoft C++ Build Tools**

1. Tải và cài đặt: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Chọn "C++ build tools" workload
3. Sau đó chạy lại: `pip install -r requirements.txt`

**Giải pháp 3: Dùng phiên bản PyYAML có sẵn wheel**

```bash
# Cài PyYAML phiên bản mới hơn (có pre-built wheel)
pip install "PyYAML>=6.0.1"

# Hoặc cài riêng trước
pip install PyYAML
pip install -r requirements.txt
```

### **Lỗi YARA rules**

- Xem `docs/ANALYSIS_TYPES.md`

### **Lỗi database**

- Xem `docs/DATABASE_SETUP.md`

### **Cấu trúc code**

- Xem `docs/STRUCTURE.md`

### **Deploy**

- Xem `docs/DEPLOYMENT.md`

## 📚 Tài Liệu Đầy Đủ

Xem **[docs/README.md](./README.md)** để biết tất cả tài liệu có sẵn.

---

**Chúc bạn sử dụng thành công! 🎉**
