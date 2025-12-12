# 📘 Hướng Dẫn Chi Tiết Dự Án Malware Detector

## 🎯 Dự Án Triển Khai Về Vấn Đề Gì?

### **Vấn Đề Chính**

Dự án **Malware Detector** là một hệ thống **phát hiện và phân tích mã độc (malware)** tự động, giải quyết các vấn đề:

1. **Phát hiện mã độc nhanh chóng**
   - Quét file trước khi sử dụng
   - Phát hiện 564+ loại malware khác nhau
   - So sánh hash với database đã biết

2. **Phân tích tĩnh (Static Analysis)**
   - Phân tích file PE (Windows executables)
   - Trích xuất strings đáng ngờ
   - Phát hiện packers, obfuscators

3. **Giao diện web dễ sử dụng**
   - Upload file/folder qua web UI
   - Xem kết quả phân tích chi tiết
   - Export báo cáo

4. **API tích hợp**
   - RESTful API đầy đủ
   - Tích hợp vào hệ thống CI/CD
   - WebSocket cho real-time updates

### **Ứng Dụng Thực Tế**

- ✅ **Bảo mật hệ thống**: Quét file trước khi chạy
- ✅ **Phân tích malware**: Nghiên cứu và phân tích mã độc
- ✅ **Tự động hóa**: Tích hợp vào hệ thống CI/CD
- ✅ **Giáo dục**: Học về malware detection và reverse engineering
- ✅ **Kiểm tra USB/storage**: Quét thiết bị lưu trữ
- ✅ **Quét folder định kỳ**: Tự động quét hệ thống

---

## 🏗️ Sơ Đồ Kiến Trúc Dự Án

### **Kiến Trúc Tổng Quan**

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  Web Browser │  │  API Client  │  │  Mobile App  │         │
│  │  (HTML/JS)   │  │  (REST API)  │  │  (Future)    │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼──────────────────┼──────────────────┼───────────────┘
          │                  │                  │
          │ HTTP/HTTPS       │ HTTP/HTTPS       │
          │                  │                  │
┌─────────▼───────────────────▼───────────────────▼───────────────┐
│                    FASTAPI APPLICATION LAYER                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    app/main.py                            │  │
│  │              (Entry Point - FastAPI App)                  │  │
│  └───────────────────────┬──────────────────────────────────┘  │
│                          │                                      │
│  ┌───────────────────────▼──────────────────────────────────┐  │
│  │              API ROUTES (app/api/v1/routes/)             │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │  │
│  │  │ scan.py  │  │ web.py   │  │ health.py│  │websocket │ │  │
│  │  │/api/scan │  │ /, /submit│ │/api/health│ │/api/ws/  │ │  │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │  │
│  └───────┼─────────────┼─────────────┼────────────┼────────┘  │
│          │             │             │            │           │
│  ┌───────▼─────────────▼─────────────▼────────────▼────────┐  │
│  │         SERVICES LAYER (app/services/)                  │  │
│  │  ┌──────────────────┐  ┌──────────────────┐            │  │
│  │  │analyzer_service  │  │ yara_service     │            │  │
│  │  │  (Orchestrator)  │  │ hash_service     │            │  │
│  │  │                  │  │static_analyzer_ │            │  │
│  │  │                  │  │    service       │            │  │
│  │  └────────┬─────────┘  └────────┬─────────┘            │  │
│  └───────────┼──────────────────────┼───────────────────────┘  │
│              │                     │                            │
└──────────────┼─────────────────────┼────────────────────────────┘
               │                     │
┌──────────────▼─────────────────────▼────────────────────────────┐
│                    CORE MODULES (src/)                           │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ StaticAnalyzer   │  │   Utils          │                    │
│  │  (PE Analysis)   │  │  (Hash, YARA)    │                    │
│  └──────────────────┘  └──────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
               │                     │
┌──────────────▼─────────────────────▼────────────────────────────┐
│                    DATA LAYER                                    │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │   DATABASE       │  │   FILE SYSTEM    │                    │
│  │   (MySQL)        │  │                  │                    │
│  │                  │  │  - uploads/      │                    │
│  │  - analyses      │  │  - yara_rules/   │                    │
│  │  - yara_matches  │  │  - Malware.json  │                    │
│  └──────────────────┘  └──────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
```

### **Luồng Xử Lý Khi Upload File**

```
1. USER UPLOAD FILE
   │
   ▼
2. API ROUTE (scan.py hoặc web.py)
   │  - Nhận file upload
   │  - Validate file
   │
   ▼
3. ANALYZER SERVICE
   │  - Orchestrator điều phối các service
   │
   ├─► HASH SERVICE
   │     - Tính SHA256, MD5
   │     - Tra cứu database Malware.json
   │
   ├─► YARA SERVICE
   │     - Load YARA rules
   │     - Quét file với 564+ rules
   │
   └─► STATIC ANALYZER SERVICE
         - Phân tích PE file
         - Trích xuất strings
         - Phát hiện capabilities
   │
   ▼
4. DATABASE REPOSITORY
   │  - Lưu kết quả phân tích
   │  - Lưu YARA matches
   │
   ▼
5. RESPONSE
   │  - Trả về JSON (API) hoặc HTML (Web UI)
   │  - Hiển thị kết quả
```

### **Cấu Trúc Thư Mục Chi Tiết**

```
PBL6_DetectMalwareApplication-develop/
│
├── 📦 app/                          # ⭐ ỨNG DỤNG WEB (FastAPI)
│   ├── main.py                      # ⭐ Entry point chính
│   │
│   ├── 🎯 core/                     # Cấu hình
│   │   ├── config.py                # Settings, YARA loading
│   │   └── dependencies.py          # Shared functions
│   │
│   ├── 🌐 api/                      # API Layer
│   │   └── v1/
│   │       └── routes/
│   │           ├── scan.py          # POST /api/scan
│   │           ├── web.py           # GET,POST / (Web UI)
│   │           ├── health.py        # GET /api/health
│   │           └── websocket.py     # WS /api/ws/{task_id}
│   │
│   ├── 📋 schemas/                  # Pydantic Models
│   │   └── scan.py                  # ScanResult schema
│   │
│   ├── ⚙️ services/                 # Business Logic
│   │   ├── analyzer_service.py      # Main orchestrator
│   │   ├── yara_service.py          # YARA scanning
│   │   ├── hash_service.py          # Hash detection
│   │   └── static_analyzer_service.py # PE analysis
│   │
│   ├── 🗄️ database/                 # Database Access
│   │   ├── connection.py            # MySQL connection
│   │   └── analysis_repository.py    # CRUD operations
│   │
│   └── 📊 models/                   # Database Models
│       └── analysis.py              # Analysis model
│
├── 🎨 frontend/                      # Frontend Files
│   ├── templates/                   # HTML Templates
│   │   ├── index.html               # Trang chủ
│   │   ├── result.html              # Kết quả phân tích
│   │   └── analyses.html            # Lịch sử phân tích
│   │
│   └── static/                      # Static Files
│       ├── css/                     # CSS files
│       └── js/                      # JavaScript files
│
├── 🔧 src/                           # Core Modules
│   ├── Analysis/
│   │   └── StaticAnalyzer.py        # PE analysis
│   ├── Database/
│   │   ├── Driver.py                # MySQL driver
│   │   └── Malware.json             # Hash database
│   └── Utils/
│       └── Utils.py                 # Utilities
│
├── 🛡️ yara_rules/                   # YARA Rules
│   └── rules/
│       └── index.yar                # 564+ YARA rules
│
├── 📁 uploads/                       # Upload folder (temporary)
├── 📝 docs/                          # Documentation
├── 🐍 venv/                          # Virtual environment
├── 📄 requirements.txt              # Python dependencies
└── 🐳 config/
    ├── docker-compose.yml           # Docker Compose
    └── Dockerfile                   # Docker image
```

---

## 🚀 Hướng Dẫn Chạy Dự Án

### **Phương Án 1: Virtual Environment (Khuyến Nghị cho Development)**

#### **Bước 1: Kích Hoạt Virtual Environment**

```powershell
# Windows PowerShell
cd "D:\pbl6\PBL6_DetectMalwareApplication-develop"
.\venv\Scripts\Activate.ps1

# Windows CMD
venv\Scripts\activate.bat

# Linux/Mac
source venv/bin/activate
```

**Kiểm tra**: Bạn sẽ thấy `(venv)` ở đầu dòng prompt.

#### **Bước 2: Cài Đặt Dependencies**

```powershell
# Đảm bảo venv đã kích hoạt (sẽ thấy (venv) ở đầu)
pip install -r config/requirements.txt
```

**Lưu ý**: Nếu gặp lỗi PyYAML trên Windows, xem phần Troubleshooting bên dưới.

#### **Bước 3: Chạy Ứng Dụng**

```powershell
# Cách 1: Dùng uvicorn (khuyến nghị)
uvicorn app.main:app --reload --host 0.0.0.0 --port 5000

# Cách 2: Chạy trực tiếp
python app/main.py
```

#### **Bước 4: Truy Cập Ứng Dụng**

Mở trình duyệt và truy cập:

- ✅ **Web UI**: http://localhost:5000
- ✅ **API Docs (Swagger)**: http://localhost:5000/api/docs
- ✅ **ReDoc**: http://localhost:5000/api/redoc
- ✅ **Health Check**: http://localhost:5000/api/health

**⚠️ Lưu ý quan trọng**: 
- ✅ Dùng: `http://localhost:5000` hoặc `http://127.0.0.1:5000`
- ❌ KHÔNG dùng: `http://0.0.0.0:5000` (sẽ báo lỗi ERR_ADDRESS_INVALID)

#### **Bước 5: Dừng Ứng Dụng**

Nhấn `Ctrl + C` trong terminal để dừng server.

Để tắt venv:
```powershell
deactivate
```

---

### **Phương Án 2: Docker (Khuyến Nghị cho Production)**

#### **Yêu Cầu:**
- Docker đã cài đặt
- 2GB+ RAM
- 5GB+ dung lượng ổ cứng

#### **Cách Chạy:**

```bash
# 1. Vào thư mục config
cd config

# 2. Chạy với docker-compose
docker-compose up -d

# 3. Xem logs
docker-compose logs -f

# 4. Truy cập: http://localhost:5000

# Dừng container
docker-compose down

# Khởi động lại
docker-compose restart
```

#### **Quản Lý Docker Container:**

```bash
# Xem danh sách containers
docker ps

# Xem logs
docker logs pbl6-malware-detector

# Dừng container
docker stop pbl6-malware-detector

# Khởi động lại
docker start pbl6-malware-detector

# Xóa container
docker rm pbl6-malware-detector
```

---

## 💾 Hướng Dẫn Kết Nối Database

### **Tại Sao Cần Database?**

Database được sử dụng để:
- ✅ Lưu lịch sử phân tích
- ✅ Thống kê malware theo thời gian
- ✅ Tìm kiếm theo SHA256, filename
- ✅ Tránh phân tích trùng lặp

**Lưu ý**: Database là **tùy chọn**. Nếu không setup database, ứng dụng vẫn hoạt động bình thường, chỉ không lưu lịch sử.

### **Bước 1: Cài Đặt MySQL**

#### **Windows:**
1. Download MySQL từ https://dev.mysql.com/downloads/mysql/
2. Hoặc sử dụng XAMPP/WAMP (đã có MySQL sẵn)

#### **Linux:**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
```

#### **Mac:**
```bash
brew install mysql
brew services start mysql
```

### **Bước 2: Cấu Hình Kết Nối**

**⭐ LƯU Ý QUAN TRỌNG**: Database sẽ **TỰ ĐỘNG được tạo** khi chạy ứng dụng, bạn **KHÔNG CẦN** tạo database thủ công!

Tạo file `.env` trong thư mục gốc của dự án:

Tạo file `.env` trong thư mục gốc của dự án:

```env
# Database Configuration
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_NAME=malwaredetection
DB_PORT=3306
```

**Lưu ý**: 
- Thay `your_password` bằng mật khẩu MySQL của bạn
- Nếu dùng XAMPP, mặc định: `DB_USER=root`, `DB_PASSWORD=""` (để trống)

### **Bước 3: Khởi Động Ứng Dụng**

Khi khởi động ứng dụng, hệ thống sẽ **TỰ ĐỘNG**:
1. ✅ Tạo database nếu chưa tồn tại
2. ✅ Tạo tables nếu chưa có

```powershell
# Kích hoạt venv
.\venv\Scripts\Activate.ps1

# Chạy ứng dụng
uvicorn app.main:app --reload --host 0.0.0.0 --port 5000
```

**Kiểm tra kết nối**:
- ✅ Database được tạo: `[OK] Database 'malwaredetection' created successfully`
- ✅ Database đã tồn tại: `[INFO] Database 'malwaredetection' already exists`
- ✅ Tables được tạo: `[OK] Database tables initialized`
- ✅ Tổng thể: `[OK] Database initialized`
- ❌ Thất bại: `[WARN] Database initialization failed` (vẫn chạy được, chỉ không lưu lịch sử)

**Ví dụ output khi khởi động thành công:**
```
[OK] Database 'malwaredetection' created successfully
[OK] Database tables initialized
[OK] Database initialized
```

### **Bước 4: Kiểm Tra Database (Tùy Chọn)**

Nếu muốn kiểm tra database đã được tạo, kết nối MySQL:

```sql
-- Kết nối MySQL
mysql -u root -p

-- Xem danh sách databases
SHOW DATABASES;

-- Sử dụng database
USE malwaredetection;

-- Xem tables đã tạo
SHOW TABLES;
```

Kết quả sẽ có 2 bảng:
- `analyses` - Lưu kết quả phân tích
- `yara_matches` - Lưu YARA matches

**Lưu ý**: Bạn **KHÔNG CẦN** làm bước này, chỉ để kiểm tra nếu muốn.

#### **Xem Dữ Liệu:**

```sql
-- Xem tất cả analyses
SELECT * FROM analyses ORDER BY created_at DESC LIMIT 10;

-- Xem số lượng malware detected
SELECT COUNT(*) FROM analyses WHERE malware_detected = TRUE;

-- Xem YARA matches
SELECT * FROM yara_matches LIMIT 10;
```

### **Cấu Trúc Database Schema**

#### **Bảng `analyses`:**

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

#### **Bảng `yara_matches`:**

```sql
CREATE TABLE yara_matches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    analysis_id INT NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    tags TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    INDEX idx_analysis_id (analysis_id),
    INDEX idx_rule_name (rule_name)
);
```

### **API Endpoints Cho Database**

#### **1. Lấy Danh Sách Analyses:**

```bash
GET /api/analyses?limit=100&offset=0
```

#### **2. Lấy Chi Tiết Analysis:**

```bash
GET /api/analyses/{analysis_id}
```

#### **3. Tìm Theo SHA256:**

```bash
GET /api/analyses/sha256/{sha256}
```

#### **4. Thống Kê:**

```bash
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

### **Troubleshooting Database**

#### **Lỗi: "Access denied for user"**

- Kiểm tra username/password trong `.env`
- Đảm bảo MySQL đang chạy
- Kiểm tra user có quyền truy cập database

#### **Lỗi: "Unknown database"**

- Tạo database: `CREATE DATABASE malwaredetection;`
- Hoặc đổi `DB_NAME` trong `.env`

#### **Database Không Bắt Buộc**

- Nếu không setup database, ứng dụng vẫn chạy
- Chỉ không lưu lịch sử phân tích
- Tất cả tính năng khác hoạt động bình thường

---

## 📖 Hướng Dẫn Chi Tiết Dự Án

### **1. Cách Hoạt Động Của Hệ Thống**

#### **A. Phát Hiện Malware Bằng YARA Rules**

1. **YARA Rules là gì?**
   - Pattern matching để tìm malware
   - Chứa các pattern (chuỗi, regex, conditions)
   - Quét file để tìm pattern khớp

2. **Cách hoạt động:**
   ```
   File Upload → Load YARA Rules → Quét File → So Sánh Pattern → Kết Quả
   ```

3. **Ví dụ YARA Rule:**
   ```yara
   rule Trojan_Win32_Example {
       strings:
           $a = "malicious_string"
           $b = /evil_[a-z]+/
       condition:
           $a and $b
   }
   ```

#### **B. Phát Hiện Bằng Hash**

1. **Hash Detection:**
   - Tính SHA256, MD5 của file
   - Tra cứu trong database `Malware.json`
   - Nếu khớp → Phát hiện malware đã biết

2. **Cách hoạt động:**
   ```
   File Upload → Tính SHA256/MD5 → Tra Cứu Database → Kết Quả
   ```

#### **C. Phân Tích Tĩnh (Static Analysis)**

1. **PE File Analysis:**
   - Phân tích cấu trúc PE (Windows executables)
   - Trích xuất imports, exports
   - Phát hiện packers, obfuscators

2. **Strings Extraction:**
   - Trích xuất strings từ file
   - Phát hiện suspicious strings

3. **Capabilities Detection:**
   - Phát hiện khả năng của malware
   - Network, file system, registry access

### **2. Các Tính Năng Chính**

#### **A. Upload File Đơn Lẻ**

1. Truy cập http://localhost:5000
2. Click "Submit File"
3. Chọn file cần phân tích
4. Xem kết quả

#### **B. Upload Folder (Nhiều Files)**

1. Truy cập http://localhost:5000
2. Click "Submit Folder"
3. Chọn folder chứa files
4. Xem kết quả tổng hợp

#### **C. Sử Dụng API**

```bash
# Quét file
curl -X POST "http://localhost:5000/api/scan" \
  -F "file=@test.exe"

# Xem lịch sử (nếu có database)
curl "http://localhost:5000/api/analyses"
```

#### **D. Xem Lịch Sử Phân Tích**

1. Truy cập http://localhost:5000/analyses
2. Xem danh sách tất cả analyses
3. Click vào analysis để xem chi tiết

### **3. Cấu Trúc Code**

#### **A. API Routes (app/api/v1/routes/)**

- `scan.py`: Xử lý `/api/scan` - Quét file
- `web.py`: Xử lý `/`, `/submit` - Web UI
- `health.py`: Xử lý `/api/health` - Health check

#### **B. Services (app/services/)**

- `analyzer_service.py`: Orchestrator chính
- `yara_service.py`: YARA scanning
- `hash_service.py`: Hash detection
- `static_analyzer_service.py`: PE analysis

#### **C. Database (app/database/)**

- `connection.py`: MySQL connection pool
- `analysis_repository.py`: CRUD operations

### **4. Các File Quan Trọng**

#### **A. app/main.py**
- Entry point chính
- Khởi tạo FastAPI app
- Load YARA rules
- Initialize database

#### **B. app/core/config.py**
- Cấu hình ứng dụng
- Đường dẫn files
- YARA rules loading

#### **C. src/Analysis/StaticAnalyzer.py**
- Phân tích PE files
- Trích xuất strings
- Phát hiện capabilities

### **5. YARA Rules**

#### **Vị Trí:**
- `yara_rules/rules/index.yar` - File chứa 564+ rules

#### **Nguồn:**
- Từ Yara-Rules project: https://github.com/Yara-Rules/rules.git

#### **Cập Nhật Rules:**
```bash
cd yara_rules
git pull origin main
```

### **6. Hash Database**

#### **Vị Trí:**
- `src/Database/Malware.json` - Database hash đã biết

#### **Cấu Trúc:**
```json
{
  "sha256": {
    "malwareType": "trojan",
    "firstSeen": "2024-01-01"
  }
}
```

---

## ⚠️ Troubleshooting

### **Lỗi: ModuleNotFoundError**

```powershell
# Đảm bảo venv đã kích hoạt
.\venv\Scripts\Activate.ps1
pip install -r config/requirements.txt
```

### **Lỗi: PyYAML trên Windows**

**Giải pháp 1: Cài đặt pre-built wheel (Khuyến nghị)**

```powershell
pip install --upgrade pip setuptools wheel
pip install --only-binary :all: PyYAML
pip install -r config/requirements.txt
```

**Giải pháp 2: Cài Microsoft C++ Build Tools**

1. Tải từ: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Chọn "C++ build tools" workload
3. Chạy lại: `pip install -r config/requirements.txt`

### **Lỗi: Port 5000 đã được sử dụng**

```powershell
# Đổi port (ví dụ 8080)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

### **Lỗi: YARA rules không load**

```powershell
python scripts/check_yara_rules.py
python scripts/fix_yara_rules.py
```

### **Lỗi: Database connection failed**

- Kiểm tra MySQL đang chạy
- Kiểm tra `.env` file
- Kiểm tra username/password
- Xem `docs/DATABASE_SETUP.md` để biết thêm

---

## 📚 Tài Liệu Tham Khảo

- **[README.md](../README.md)** - Tổng quan dự án
- **[QUICK_START.md](./QUICK_START.md)** - Hướng dẫn bắt đầu nhanh
- **[STRUCTURE.md](./STRUCTURE.md)** - Cấu trúc và kiến trúc
- **[ANALYSIS_TYPES.md](./ANALYSIS_TYPES.md)** - Giải thích phân tích malware
- **[DATABASE_SETUP.md](./DATABASE_SETUP.md)** - Setup database
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Deploy production

---

## 🎯 Tóm Tắt

### **Dự án này làm gì?**
→ Hệ thống phát hiện và phân tích mã độc tự động

### **Cách chạy?**
→ Kích hoạt venv → Cài dependencies → Chạy `uvicorn app.main:app --reload`

### **Cách kết nối database?**
→ Tạo `.env` file → Cấu hình MySQL → Khởi động ứng dụng (tự động tạo tables)

### **Cấu trúc kiến trúc?**
→ Client → FastAPI → Services → Core Modules → Database/File System

---

**Chúc bạn sử dụng thành công! 🚀**

