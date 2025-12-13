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

### 🔍 1. Health Check
```http
GET /api/health
```
**Tác dụng**: Kiểm tra trạng thái hệ thống, số lượng YARA rules đã load
**Response**:
```json
{
  "status": "healthy",
  "yara_rules_loaded": true,
  "yara_rule_count": 564
}
```

---

### 📤 2. Scan File
```http
POST /api/scan
Content-Type: multipart/form-data

file: <file>
```
**Tác dụng**: Upload và quét một file để phát hiện malware
- Phân tích static (YARA, Hash, PE)
- Lưu kết quả vào database
- Trả về kết quả phân tích chi tiết

**Response**:
```json
{
  "filename": "test.exe",
  "sha256": "...",
  "md5": "...",
  "malware_detected": true,
  "yara_matches": [...],
  "pe_info": {...},
  "suspicious_strings": [...],
  "capabilities": {...},
  "analysis_time": 2.5
}
```

---

### 📋 3. Analyses Management

#### 3.1. Get All Analyses
```http
GET /api/analyses?limit=100&offset=0
```
**Tác dụng**: Lấy danh sách tất cả analyses với pagination
- `limit`: Số lượng kết quả (1-1000)
- `offset`: Vị trí bắt đầu

#### 3.2. Get Analysis by ID
```http
GET /api/analyses/{analysis_id}
```
**Tác dụng**: Lấy chi tiết một analysis theo ID

#### 3.3. Get Analysis by SHA256
```http
GET /api/analyses/sha256/{sha256}
```
**Tác dụng**: Tìm analysis theo SHA256 hash

#### 3.4. Get Statistics
```http
GET /api/analyses/stats/summary
```
**Tác dụng**: Lấy thống kê tổng quan (tổng số analyses, malware detected, clean files, recent 24h)

#### 3.5. Delete Analysis
```http
DELETE /api/analyses/{analysis_id}
```
**Tác dụng**: Xóa một analysis và tất cả dữ liệu liên quan (ratings, YARA matches)
- Xóa YARA matches trước (foreign key constraint)
- Xóa ratings liên quan
- Xóa analysis

**Response**:
```json
{
  "message": "Analysis deleted successfully",
  "id": 123
}
```

---

### 📦 4. Batch Scan

#### 4.1. Scan Folder
```http
POST /api/scan/folder
Content-Type: application/json

{
  "folder_path": "/path/to/folder",
  "file_extensions": ["exe", "dll", "pdf"],
  "max_files": 100
}
```
**Tác dụng**: Quét tất cả file trong một folder
- Quét background (async)
- Trả về `batch_id` để theo dõi tiến trình

#### 4.2. Scan Archive
```http
POST /api/scan/batch
Content-Type: multipart/form-data

archive: <zip/tar file>
```
**Tác dụng**: Upload file zip/tar và quét tất cả file bên trong
- Tự động extract archive
- Quét tất cả file trong archive

#### 4.3. Get Batch Status
```http
GET /api/scan/batch/{batch_id}/status
```
**Tác dụng**: Kiểm tra trạng thái batch scan (pending, processing, completed, failed)

#### 4.4. Get Batch Results
```http
GET /api/scan/batch/{batch_id}
```
**Tác dụng**: Lấy kết quả chi tiết của batch scan (danh sách file đã quét, lỗi nếu có)

---

### ⭐ 5. Ratings System

#### 5.1. Create Rating
```http
POST /api/ratings
Content-Type: application/json

{
  "analysis_id": 1,
  "rating": 5,
  "comment": "Very accurate detection",
  "reviewer_name": "John Doe",
  "tags": ["accurate", "helpful"]
}
```
**Tác dụng**: Tạo đánh giá cho một analysis (1-5 sao, comment, tags)

#### 5.2. Get Ratings for Analysis
```http
GET /api/ratings/{analysis_id}
```
**Tác dụng**: Lấy tất cả đánh giá của một analysis

#### 5.3. Get Rating by ID
```http
GET /api/ratings/detail/{rating_id}
```
**Tác dụng**: Lấy chi tiết một đánh giá theo ID

#### 5.4. Update Rating
```http
PUT /api/ratings/{rating_id}
Content-Type: application/json

{
  "rating": 4,
  "comment": "Updated comment",
  "tags": ["accurate"]
}
```
**Tác dụng**: Cập nhật đánh giá đã tạo

#### 5.5. Delete Rating
```http
DELETE /api/ratings/{rating_id}
```
**Tác dụng**: Xóa một đánh giá

#### 5.6. Get Rating Statistics
```http
GET /api/ratings/stats/{analysis_id}
```
**Tác dụng**: Lấy thống kê đánh giá (tổng số, điểm trung bình, phân bố điểm, số comment)

---

### 🔎 6. Search

#### 6.1. Search Analyses
```http
GET /api/search/analyses?q=keyword&limit=50&offset=0
```
**Tác dụng**: Tìm kiếm analyses theo filename, SHA256, hoặc MD5
- `q`: Từ khóa tìm kiếm
- `limit`: Số lượng kết quả (1-100)
- `offset`: Vị trí bắt đầu

---

### 📥 7. Export Data

#### 7.1. Export Analyses CSV
```http
GET /api/export/analyses/csv?limit=1000&offset=0
```
**Tác dụng**: Export danh sách analyses ra file CSV
- Tối đa 10000 records
- Download file CSV

#### 7.2. Export Analyses JSON
```http
GET /api/export/analyses/json?limit=1000&offset=0
```
**Tác dụng**: Export danh sách analyses ra file JSON
- Tối đa 10000 records
- Download file JSON

#### 7.3. Export Analyses Excel
```http
GET /api/export/analyses/excel?limit=1000&offset=0
```
**Tác dụng**: Export danh sách analyses ra file Excel (XLSX)
- Tối đa 10000 records
- Format đẹp với headers có style
- Auto-adjust column widths
- Download file XLSX

---

### 🔌 8. WebSocket (Real-time)

#### 8.1. WebSocket Progress
```http
WS /api/ws/{task_id}
```
**Tác dụng**: Real-time progress updates cho dynamic analysis
- Dùng cho sandbox analysis (sẽ implement sau)
- Gửi progress updates qua WebSocket

---

## 📊 Tổng Hợp API Endpoints

| Method | Endpoint | Tác Dụng |
|--------|----------|----------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Quét một file |
| `GET` | `/api/analyses` | Lấy danh sách analyses |
| `GET` | `/api/analyses/{id}` | Lấy chi tiết analysis |
| `GET` | `/api/analyses/sha256/{sha256}` | Tìm analysis theo SHA256 |
| `GET` | `/api/analyses/stats/summary` | Thống kê tổng quan |
| `DELETE` | `/api/analyses/{id}` | Xóa analysis |
| `POST` | `/api/scan/folder` | Quét folder |
| `POST` | `/api/scan/batch` | Quét archive |
| `GET` | `/api/scan/batch/{batch_id}/status` | Trạng thái batch scan |
| `GET` | `/api/scan/batch/{batch_id}` | Kết quả batch scan |
| `POST` | `/api/ratings` | Tạo đánh giá |
| `GET` | `/api/ratings/{analysis_id}` | Lấy đánh giá của analysis |
| `GET` | `/api/ratings/detail/{rating_id}` | Lấy chi tiết đánh giá |
| `PUT` | `/api/ratings/{rating_id}` | Cập nhật đánh giá |
| `DELETE` | `/api/ratings/{rating_id}` | Xóa đánh giá |
| `GET` | `/api/ratings/stats/{analysis_id}` | Thống kê đánh giá |
| `GET` | `/api/search/analyses` | Tìm kiếm analyses |
| `GET` | `/api/export/analyses/csv` | Export CSV |
| `GET` | `/api/export/analyses/json` | Export JSON |
| `GET` | `/api/export/analyses/excel` | Export Excel |
| `WS` | `/api/ws/{task_id}` | WebSocket progress |

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

