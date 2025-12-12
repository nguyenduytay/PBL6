# 📚 Tài Liệu Dự Án - Malware Detector

Chào mừng đến với tài liệu dự án Malware Detector! Đây là hướng dẫn để bạn tìm hiểu và sử dụng dự án.

## 📖 Mục Lục Tài Liệu

### 🎯 **Bắt Đầu Nhanh**

1. **[README.md](../README.md)** (Root)
   - **Mục đích**: Tổng quan dự án, cách chạy, cấu trúc cơ bản
   - **Dành cho**: Người mới bắt đầu, muốn hiểu tổng quan
   - **Nội dung**: 
     - Tác dụng và mục đích dự án
     - Cách chạy dự án
     - Cấu trúc cơ bản
     - Link YARA rules

### 📁 **Cấu Trúc & Kiến Trúc**

2. **[STRUCTURE.md](./STRUCTURE.md)**
   - **Mục đích**: Giải thích chi tiết cấu trúc dự án sau khi tổ chức lại
   - **Dành cho**: Developers muốn hiểu kiến trúc code
   - **Nội dung**:
     - Cấu trúc thư mục mới (frontend/, app/)
     - Cách sử dụng templates, CSS modules, JS modules
     - Best practices
     - Hướng dẫn phát triển tiếp

### 🔍 **Phân Tích Malware**

3. **[ANALYSIS_TYPES.md](./ANALYSIS_TYPES.md)**
   - **Mục đích**: Giải thích các loại phân tích malware và cách hoạt động
   - **Dành cho**: Người muốn hiểu cách hệ thống phát hiện malware
   - **Nội dung**:
     - YARA Rules là gì?
     - Static Analysis vs Dynamic Analysis
     - Hash-based detection
     - Có cần database không?
     - Khuyến nghị cải thiện

### 💾 **Database & Lịch Sử**

4. **[DATABASE_SETUP.md](./DATABASE_SETUP.md)**
   - **Mục đích**: Hướng dẫn setup database để lưu lịch sử phân tích
   - **Dành cho**: Người muốn lưu lịch sử phân tích
   - **Nội dung**:
     - Cấu hình database (MySQL)
     - Database schema
     - API endpoints cho lịch sử
     - Troubleshooting

### 🚀 **Deployment**

5. **[DEPLOYMENT.md](./DEPLOYMENT.md)**
   - **Mục đích**: Hướng dẫn deploy dự án lên web/server
   - **Dành cho**: Người muốn deploy production
   - **Nội dung**:
     - Docker deployment
     - VPS/Cloud Server deployment
     - PaaS platforms (Heroku, Railway)
     - Nginx reverse proxy

### 📘 **Hướng Dẫn Chi Tiết**

6. **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** ⭐ **MỚI**
   - **Mục đích**: Hướng dẫn chi tiết toàn diện về dự án
   - **Dành cho**: Tất cả mọi người muốn hiểu sâu về dự án
   - **Nội dung**:
     - Giải thích vấn đề dự án giải quyết
     - Sơ đồ kiến trúc dự án (ASCII art)
     - Hướng dẫn chạy dự án chi tiết
     - Hướng dẫn kết nối database từng bước
     - Luồng xử lý khi upload file
     - Troubleshooting đầy đủ

## 🗺️ Hướng Dẫn Đọc Tài Liệu

### **Cho Người Mới Bắt Đầu:**

1. Đọc **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** ⭐ - Hướng dẫn chi tiết toàn diện
2. Đọc **[README.md](../README.md)** - Hiểu tổng quan dự án
3. Đọc **[STRUCTURE.md](./STRUCTURE.md)** - Hiểu cấu trúc code
4. Đọc **[ANALYSIS_TYPES.md](./ANALYSIS_TYPES.md)** - Hiểu cách phân tích hoạt động

### **Cho Developers:**

1. **[STRUCTURE.md](./STRUCTURE.md)** - Kiến trúc và best practices
2. **[DATABASE_SETUP.md](./DATABASE_SETUP.md)** - Setup database
3. **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Deploy production

### **Cho Người Dùng:**

1. **[README.md](../README.md)** - Cách chạy và sử dụng
2. **[ANALYSIS_TYPES.md](./ANALYSIS_TYPES.md)** - Hiểu kết quả phân tích

## 📋 Tóm Tắt Nội Dung

| File | Mục Đích | Độ Khó | Thời Gian Đọc |
|------|----------|--------|---------------|
| **HUONG_DAN_CHI_TIET.md** ⭐ | Hướng dẫn chi tiết toàn diện | ⭐⭐ Trung bình | 30 phút |
| **README.md** | Tổng quan, cách chạy | ⭐ Dễ | 10 phút |
| **STRUCTURE.md** | Kiến trúc code | ⭐⭐ Trung bình | 15 phút |
| **ANALYSIS_TYPES.md** | Giải thích phân tích | ⭐⭐ Trung bình | 20 phút |
| **DATABASE_SETUP.md** | Setup database | ⭐⭐⭐ Khó | 15 phút |
| **DEPLOYMENT.md** | Deploy production | ⭐⭐⭐ Khó | 30 phút |

## 🎯 Câu Hỏi Thường Gặp

### **Dự án này làm gì?**
→ Đọc **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** phần "Dự Án Triển Khai Về Vấn Đề Gì?" hoặc **[README.md](../README.md)** phần "Tác dụng và Mục đích"

### **Cách chạy dự án?**
→ Đọc **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** phần "Hướng Dẫn Chạy Dự Án" hoặc **[README.md](../README.md)** phần "Cách Chạy Dự Án"

### **Sơ đồ kiến trúc dự án?**
→ Đọc **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** phần "Sơ Đồ Kiến Trúc Dự Án"

### **Cách kết nối database?**
→ Đọc **[HUONG_DAN_CHI_TIET.md](./HUONG_DAN_CHI_TIET.md)** phần "Hướng Dẫn Kết Nối Database"

### **YARA Rules là gì? Có cần database không?**
→ Đọc **[ANALYSIS_TYPES.md](./ANALYSIS_TYPES.md)**

### **Cấu trúc code như thế nào?**
→ Đọc **[STRUCTURE.md](./STRUCTURE.md)**

### **Làm sao lưu lịch sử phân tích?**
→ Đọc **[DATABASE_SETUP.md](./DATABASE_SETUP.md)**

### **Làm sao deploy lên web?**
→ Đọc **[DEPLOYMENT.md](./DEPLOYMENT.md)**

## 🔗 Liên Kết Nhanh

- **Chạy dự án**: `python -m uvicorn app.main:app --reload`
- **API Docs**: http://localhost:5000/api/docs
- **Web UI**: http://localhost:5000
- **Health Check**: http://localhost:5000/api/health

## 📝 Ghi Chú

- Tất cả tài liệu đều bằng tiếng Việt để dễ hiểu
- Code comments cũng bằng tiếng Việt
- Có ví dụ code trong mỗi file
- Cập nhật thường xuyên khi có thay đổi

## 🆘 Cần Hỗ Trợ?

Nếu có câu hỏi không tìm thấy trong tài liệu:
1. Kiểm tra lại các file trong `docs/`
2. Xem code comments trong source code
3. Kiểm tra API docs tại `/api/docs`

---

**Happy Coding! 🚀**

