# 🚀 Backend - Malware Detector API

Backend API cho hệ thống phát hiện malware sử dụng **FastAPI** (Python).

## 📋 Yêu Cầu

- Python 3.10+
- MySQL (tùy chọn - để lưu lịch sử phân tích)
- YARA engine (tự động cài với dependencies)

## 🏗️ Cấu Trúc Dự Án

```
backend/
│
├── 📦 app/                          # FastAPI Application
│   ├── main.py                      # ⭐ Entry point chính
│   │
│   ├── 🌐 api/                      # API Layer
│   │   └── v1/
│   │       └── routes/
│   │           ├── scan.py         # POST /api/scan - Quét file
│   │           ├── analyses.py     # GET /api/analyses - Lịch sử phân tích
│   │           ├── health.py       # GET /api/health - Health check
│   │           └── websocket.py   # WS /api/ws/{task_id} - Real-time
│   │
│   ├── ⚙️ services/                  # Business Logic Layer
│   │   ├── analyzer_service.py      # Orchestrator chính
│   │   ├── yara_service.py          # YARA scanning
│   │   ├── hash_service.py          # Hash detection
│   │   └── static_analyzer_service.py # PE analysis
│   │
│   ├── 🗄️ database/                 # Database Layer
│   │   ├── connection.py            # MySQL connection pool
│   │   └── analysis_repository.py   # CRUD operations
│   │
│   ├── 📋 schemas/                  # Pydantic Models
│   │   └── scan.py                  # Data validation schemas
│   │
│   ├── 🎯 core/                     # Core Configuration
│   │   ├── config.py                # Settings, paths, YARA loading
│   │   └── dependencies.py          # Shared dependencies
│   │
│   └── 📊 models/                    # Database Models
│       └── analysis.py              # Analysis model
│
├── 🔧 src/                           # Core Modules (Reusable)
│   ├── Analysis/
│   │   └── StaticAnalyzer.py        # PE file analysis
│   ├── Database/
│   │   ├── Driver.py                # MySQL driver
│   │   └── Malware.json             # Hash database
│   └── Utils/
│       └── Utils.py                 # Utilities (hash, YARA)
│
├── 🛡️ yara_rules/                   # YARA Rules Database
│   └── rules/
│       └── index.yar                # 564+ YARA rules
│
├── 📁 uploads/                       # Upload folder (temporary files)
├── 📝 scripts/                       # Utility scripts
├── 🐳 config/                        # Docker configuration
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── requirements.txt                  # Python dependencies
└── venv/                             # Virtual environment (optional)
```

## 🚀 Cách Chạy

### Phương Án 1: Virtual Environment (Development) ⭐

#### Bước 1: Tạo và Kích Hoạt Virtual Environment

```powershell
# Windows PowerShell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1

# Windows CMD
venv\Scripts\activate.bat

# Linux/Mac
source venv/bin/activate
```

**Kiểm tra**: Bạn sẽ thấy `(venv)` ở đầu dòng prompt.

#### Bước 2: Cài Đặt Dependencies

```powershell
# Đảm bảo venv đã kích hoạt
pip install -r requirements.txt
```

#### Bước 3: Cấu Hình Database (Tùy Chọn)

Tạo file `.env` trong thư mục `backend/`:

```env
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_NAME=malwaredetection
DB_PORT=3306
```

**Lưu ý**: 
- Database sẽ **TỰ ĐỘNG được tạo** khi chạy ứng dụng
- Nếu không cấu hình database, ứng dụng vẫn chạy được (chỉ không lưu lịch sử)

#### Bước 4: Chạy Ứng Dụng

```powershell
# Cách 1: Dùng uvicorn (khuyến nghị)
uvicorn app.main:app --reload --host 0.0.0.0 --port 5000

# Cách 2: Chạy trực tiếp
python app/main.py
```

#### Bước 5: Kiểm Tra

Mở trình duyệt và truy cập:

- ✅ **API Docs (Swagger)**: http://localhost:5000/api/docs
- ✅ **ReDoc**: http://localhost:5000/api/redoc
- ✅ **Health Check**: http://localhost:5000/api/health

---

### Phương Án 2: Docker (Production)

```bash
cd backend/config
docker-compose up -d
```

---

## 📡 API Endpoints

### 1. Health Check
```http
GET /api/health
```

Response:
```json
{
  "status": "healthy",
  "yara_rules_loaded": true,
  "yara_rule_count": 564
}
```

### 2. Scan File
```http
POST /api/scan
Content-Type: multipart/form-data

file: <file>
```

Response:
```json
{
  "filename": "test.exe",
  "sha256": "...",
  "md5": "...",
  "malware_detected": true,
  "yara_matches": [...],
  "pe_info": {...},
  "analysis_time": 2.5
}
```

### 3. Get Analyses
```http
GET /api/analyses?limit=100&offset=0
```

### 4. Get Analysis Detail
```http
GET /api/analyses/{id}
```

### 5. Get Statistics
```http
GET /api/analyses/stats/summary
```

---

## 🔧 Cấu Hình

### Environment Variables

Tạo file `.env` trong thư mục `backend/`:

```env
# Database (Optional)
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_NAME=malwaredetection
DB_PORT=3306

# Server
HOST=0.0.0.0
PORT=5000
```

### CORS Configuration

Backend đã được cấu hình CORS để cho phép React frontend gọi API:

- `http://localhost:3000` (React dev server)
- `http://localhost:5173` (Vite dev server)

---

## 🗄️ Database

### Tự Động Tạo Database

Khi khởi động ứng dụng, hệ thống sẽ **TỰ ĐỘNG**:
1. ✅ Tạo database `malwaredetection` nếu chưa tồn tại
2. ✅ Tạo bảng `analyses` nếu chưa có
3. ✅ Tạo bảng `yara_matches` nếu chưa có

### Database Schema

**Bảng `analyses`:**
- `id` - Primary key
- `filename` - Tên file
- `sha256`, `md5` - Hash values
- `malware_detected` - Boolean
- `yara_matches` - JSON
- `pe_info` - JSON
- `created_at` - Timestamp

**Bảng `yara_matches`:**
- `id` - Primary key
- `analysis_id` - Foreign key
- `rule_name` - Tên YARA rule
- `tags`, `description` - Thông tin rule

---

## 🛡️ YARA Rules

### Vị Trí
- `yara_rules/rules/index.yar` - File chứa 564+ YARA rules

### Nguồn
- Từ Yara-Rules project: https://github.com/Yara-Rules/rules.git

### Cập Nhật Rules
```bash
cd yara_rules
git pull origin main
```

---

## 📦 Dependencies Chính

### **Bắt Buộc:**
- **fastapi** - Web framework
- **uvicorn** - ASGI server
- **python-multipart** - File upload support (BẮT BUỘC)
- **aiomysql** - MySQL async driver (CẦN để kết nối database)
- **yara-python** - YARA engine (BẮT BUỘC)
- **pefile** - PE file analysis
- **python-dotenv** - Environment variables

### **MySQL Connection:**
- ✅ **aiomysql==0.2.0** - **CẦN THIẾT** để kết nối MySQL
- ✅ **PyMySQL** - Dependency của aiomysql (tự động cài)

**Lưu ý:** Database là **tùy chọn**. Nếu không cấu hình MySQL, ứng dụng vẫn chạy được (chỉ không lưu lịch sử phân tích).

Xem đầy đủ trong `requirements.txt` hoặc `REQUIREMENTS_GUIDE.md` để biết chi tiết.

---

## 🧪 Test

### Test Health Check
```bash
curl http://localhost:5000/api/health
```

### Test Scan File
```bash
curl -X POST "http://localhost:5000/api/scan" \
  -F "file=@test.exe"
```

---

## ⚠️ Troubleshooting

### Lỗi: ModuleNotFoundError
```powershell
# Đảm bảo venv đã kích hoạt
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Lỗi: Port 5000 đã được sử dụng
```powershell
# Đổi port
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

### Lỗi: Database connection failed
- Kiểm tra MySQL đang chạy
- Kiểm tra `.env` file
- Database sẽ tự động được tạo nếu chưa có

### Lỗi: YARA rules không load
- Kiểm tra file `yara_rules/rules/index.yar` tồn tại
- Chạy: `python scripts/check_yara_rules.py`

---

## 📚 Tài Liệu Tham Khảo

- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **YARA Rules**: https://github.com/Yara-Rules/rules
- **API Documentation**: http://localhost:5000/api/docs (khi server chạy)

---

## 🎯 Tóm Tắt

- **Framework**: FastAPI (Python)
- **Server**: Uvicorn (ASGI)
- **Database**: MySQL (tùy chọn)
- **Port**: 5000
- **API Base URL**: http://localhost:5000/api

**Chúc bạn sử dụng thành công! 🚀**

