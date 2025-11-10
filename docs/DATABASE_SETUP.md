# 💾 Hướng Dẫn Setup Database cho Lịch Sử Phân Tích

## 📋 Tổng Quan

Hệ thống đã được tích hợp để **tự động lưu lịch sử phân tích** vào database.

## ⚙️ Cấu Hình Database

### **Option 1: Sử dụng MySQL (Khuyến nghị)**

1. **Cài đặt MySQL**:

```bash
# Windows: Download từ mysql.com
# Hoặc sử dụng XAMPP/WAMP
```

2. **Tạo database**:

```sql
CREATE DATABASE malwaredetection;
```

3. **Cấu hình trong `.env` hoặc environment variables**:

```env
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_NAME=malwaredetection
DB_PORT=3306
```

### **Option 2: Không dùng Database (Optional)**

Nếu không setup database, hệ thống vẫn hoạt động bình thường:

- ✅ Phân tích vẫn chạy được
- ✅ Kết quả vẫn trả về
- ❌ Chỉ không lưu lịch sử

## 🗄️ Database Schema

Database sẽ **tự động tạo tables** khi ứng dụng khởi động (nếu kết nối thành công).

### Bảng `analyses`

```sql
CREATE TABLE analyses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255) NOT NULL,
    sha256 VARCHAR(64),
    md5 VARCHAR(32),
    file_size BIGINT,
    upload_time DATETIME,
    analysis_time FLOAT DEFAULT 0.0,
    malware_detected BOOLEAN DEFAULT FALSE,
    yara_matches JSON,
    pe_info JSON,
    suspicious_strings JSON,
    capabilities JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sha256 (sha256),
    INDEX idx_created_at (created_at),
    INDEX idx_malware_detected (malware_detected)
);
```

### Bảng `yara_matches`

```sql
CREATE TABLE yara_matches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    analysis_id INT NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    tags TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
```

## 📝 Sử Dụng

### **Tự Động Lưu**

Mỗi khi phân tích file qua API `/api/scan`, kết quả sẽ **tự động lưu** vào database (nếu database available).

```python
# Trong analyzer_service.py
analysis_data = await analyzer_service.analyze_and_save(filepath, filename)
# → Tự động lưu vào database (nếu có)
```

### **API Endpoints**

#### 1. **Lấy danh sách analyses**

```http
GET /api/analyses?limit=100&offset=0
```

#### 2. **Lấy chi tiết analysis**

```http
GET /api/analyses/{analysis_id}
```

#### 3. **Tìm theo SHA256**

```http
GET /api/analyses/sha256/{sha256}
```

#### 4. **Thống kê**

```http
GET /api/analyses/stats/summary
```

Response:

```json
{
  "total_analyses": 150,
  "malware_detected": 45,
  "clean_files": 105,
  "recent_24h": 12
}
```

## ✅ Kiểm Tra

1. **Chạy ứng dụng**:

```bash
python -m uvicorn app.main:app --reload
```

2. **Kiểm tra database connection**:

- Nếu thành công: `[OK] Database initialized`
- Nếu thất bại: `[WARN] Database initialization failed` (vẫn chạy được)

3. **Phân tích một file**:

```bash
curl -X POST "http://localhost:5000/api/scan" \
  -F "file=@test.exe"
```

4. **Xem lịch sử**:

```bash
curl "http://localhost:5000/api/analyses"
```

## 🎯 Lợi Ích

- ✅ **Lịch sử đầy đủ**: Mọi lần phân tích đều được lưu
- ✅ **Thống kê**: Dễ dàng tạo báo cáo
- ✅ **Tìm kiếm**: Tìm theo SHA256, filename, date
- ✅ **Performance**: Index trên SHA256 để query nhanh
- ✅ **Tránh trùng lặp**: Có thể check xem file đã phân tích chưa

## 🔧 Troubleshooting

### Lỗi: "Access denied for user"

- Kiểm tra username/password trong `.env`
- Đảm bảo MySQL đang chạy
- Kiểm tra user có quyền truy cập database

### Lỗi: "Unknown database"

- Tạo database: `CREATE DATABASE malwaredetection;`
- Hoặc đổi `DB_NAME` trong `.env`

### Database không bắt buộc

- Nếu không setup database, ứng dụng vẫn chạy
- Chỉ không lưu lịch sử phân tích
- Tất cả tính năng khác hoạt động bình thường
