# 🛡️ Malware Detector Web Application

Ứng dụng web phát hiện mã độc chuyên nghiệp sử dụng YARA rules và hash-based detection.

## 🎯 Tác dụng và Mục đích của Dự án

Dự án này là một **hệ thống phát hiện mã độc (malware detection)** toàn diện với các tính năng:

### ✅ Chức năng chính:

1. **Phát hiện Malware tự động**

   - Quét file đơn lẻ hoặc toàn bộ folder
   - Phát hiện 564+ loại malware khác nhau qua YARA rules
   - So sánh hash với database malware (SHA256, MD5)

2. **Phân tích tĩnh (Static Analysis)**

   - Phân tích cấu trúc file PE (Windows executables)
   - Trích xuất strings đáng ngờ
   - Phát hiện packers, obfuscators
   - Tích hợp Capa framework (nếu có)

3. **Giao diện Web thân thiện**

   - Upload file/folder qua web UI
   - Xem kết quả phân tích chi tiết
   - Export báo cáo phân tích

4. **API cho tích hợp**
   - RESTful API đầy đủ
   - Swagger/OpenAPI documentation tự động
   - WebSocket cho real-time updates (tương lai)

### 🎯 Mục đích sử dụng:

- **Bảo mật hệ thống**: Quét file trước khi chạy
- **Phân tích malware**: Nghiên cứu và phân tích mã độc
- **Tự động hóa**: Tích hợp vào hệ thống CI/CD
- **Giáo dục**: Học về malware detection và reverse engineering

### 📊 Ứng dụng thực tế:

- ✅ Quét file download trước khi mở
- ✅ Kiểm tra USB/storage devices
- ✅ Quét folder hệ thống định kỳ
- ✅ API tích hợp vào hệ thống bảo mật khác
- ✅ Nghiên cứu và phân tích malware samples

---

## 🔗 Link YARA Rules

https://github.com/Yara-Rules/rules.git

## 📁 Cấu trúc Dự án - Hướng Dẫn Phát Triển

Dự án được tổ chức theo **kiến trúc web chuẩn** (Standard Web Architecture) để dễ bảo trì và mở rộng.

```
PBL6_DetectMalwareApplication-develop/
│
├── 📦 app/                          # ⭐ ỨNG DỤNG WEB (FastAPI)
│   ├── main.py                      # ⭐ Entry point chính - CHẠY TỪ ĐÂY
│   │
│   ├── 🎯 core/                     # Cấu hình và dependencies chung
│   │   ├── config.py                # Settings, đường dẫn, YARA loading
│   │   └── dependencies.py         # Shared functions (render_template, etc.)
│   │
│   ├── 🌐 api/                      # API Layer - Xử lý HTTP requests
│   │   └── v1/                      # API version 1
│   │       ├── __init__.py          # Router aggregation
│   │       └── routes/              # API endpoints
│   │           ├── scan.py         # POST /api/scan - Quét file
│   │           ├── health.py       # GET /api/health - Health check
│   │           ├── websocket.py    # WS /api/ws/{task_id} - Real-time updates
│   │           └── web.py          # GET,POST / - Web UI (HTML pages)
│   │
│   ├── 📋 schemas/                  # Pydantic Models - Data validation
│   │   └── scan.py                  # ScanResult, AnalysisResult schemas
│   │
│   ├── ⚙️ services/                 # Business Logic Layer - Logic xử lý
│   │   ├── analyzer_service.py      # File analysis logic (YARA + Hash)
│   │   └── yara_service.py         # YARA scanning service
│   │
│   ├── 🎨 templates/                # HTML Templates (Jinja2)
│   │   ├── index.html               # Trang chủ - Form upload
│   │   └── result.html             # Trang kết quả phân tích
│   │
│   ├── 🖼️ static/                   # Static Files (CSS, JS, Images)
│   │   ├── css/
│   │   │   └── style.css           # CSS chính - THIẾT KẾ GIAO DIỆN Ở ĐÂY
│   │   ├── js/
│   │   │   └── main.js             # JavaScript chính
│   │   └── images/                 # Images, logos
│   │
│   ├── web_app.py                   # Flask app (legacy - có thể xóa)
│   └── fastapi_app.py              # FastAPI app (legacy - có thể xóa)
│
├── 🔧 src/                           # Source Code - Logic tái sử dụng
│   ├── Analysis/                    # Analysis Modules
│   │   └── StaticAnalyzer.py      # PE analysis, strings, Capa integration
│   ├── Database/                    # Database Access
│   │   ├── Driver.py               # MySQL connection
│   │   └── Malware.py             # Malware models/queries
│   ├── Models/                      # Data Models
│   └── Utils/                       # Utility Functions
│       ├── Utils.py                # Hash, YARA utilities
│       └── Bcolors.py              # Console colors
│
├── 📜 scripts/                       # Scripts tiện ích
│   ├── check_yara_rules.py         # Kiểm tra YARA rules
│   └── test_complete_system.py     # Test toàn bộ hệ thống
│
├── 🛡️ yara_rules/                   # YARA Rules Database
│   └── rules/
│       └── index.yar                # 564+ YARA rules từ Yara-Rules project
│
├── 📁 config/                        # Configuration Files
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Docker image configuration
│   └── docker-compose.yml          # Docker Compose configuration
│
├── 📤 uploads/                       # Thư mục upload file tạm (auto cleanup)
├── 📝 logs/                          # Application logs (nếu có)
├── 🐍 venv/                          # Python virtual environment
│
└── 📄 Documentation Files
    ├── README.md                    # File này - Hướng dẫn tổng quan
    ├── DEPLOYMENT.md                # Hướng dẫn deploy lên web
    ├── API_WEB_ARCHITECTURE.md      # Giải thích kiến trúc API + Web
    └── Procfile                     # Cho PaaS platforms (Heroku, Railway)
```

### 🏗️ Kiến trúc Development Flow

```
📥 Request (HTTP)
    ↓
🌐 api/v1/routes/ (Router) → Nhận request, validate
    ↓
📋 schemas/ → Validate data với Pydantic
    ↓
⚙️ services/ → Business logic (phân tích file)
    ↓
🔧 src/ → Core utilities (YARA, Hash, Database)
    ↓
📤 Response (JSON/HTML)
```

### 📝 Quy tắc Phát Triển

1. **Routes (API)** → Chỉ xử lý HTTP, gọi services
2. **Services** → Chứa business logic chính
3. **Schemas** → Định nghĩa data models (Pydantic)
4. **src/** → Code tái sử dụng, không phụ thuộc vào web framework
5. **Templates/Static** → Chỉ HTML/CSS/JS, không có logic phức tạp

### 🔄 Flow khi thêm tính năng mới

1. Thêm route trong `app/api/v1/routes/`
2. Thêm schema trong `app/schemas/` (nếu cần)
3. Thêm logic trong `app/services/`
4. Sử dụng utilities từ `src/` nếu có
5. Cập nhật templates nếu là web feature

## 📚 Tài Liệu

**Xem [docs/README.md](docs/README.md) để biết tất cả tài liệu có sẵn!**

Tài liệu bao gồm:
- 📖 **[QUICK_START.md](docs/QUICK_START.md)** - Hướng dẫn bắt đầu nhanh (5 phút)
- 📁 **[STRUCTURE.md](docs/STRUCTURE.md)** - Cấu trúc và kiến trúc dự án
- 🔍 **[ANALYSIS_TYPES.md](docs/ANALYSIS_TYPES.md)** - Giải thích cách phân tích malware
- 💾 **[DATABASE_SETUP.md](docs/DATABASE_SETUP.md)** - Setup database cho lịch sử
- 🚀 **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Hướng dẫn deploy production

## 🚀 Cách Chạy Dự Án

Có 3 phương án chạy dự án:

1. **🐍 Virtual Environment (venv)** - Phát triển và test local ⭐
2. **🐳 Docker** - Chạy trong container, sẵn sàng cho production
3. **📦 Docker Compose** - Deploy đơn giản với Docker

---

### Phương án 1: 🐍 Virtual Environment (venv) - Khuyến nghị cho Development

**Khi nào dùng:** Khi đang phát triển, test, debug code.

#### ⚡ Quick Start (3 bước)

#### Bước 1: Kích hoạt môi trường ảo venv

```powershell
# Mở PowerShell/CMD và chuyển vào thư mục dự án
cd "D:\pbl6\SOURCE MalwareDetector\PBL6_DetectMalwareApplication-develop"

# Kích hoạt venv (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Hoặc (Windows CMD)
venv\Scripts\activate.bat

# Hoặc (Linux/Mac)
source venv/bin/activate
```

**Kiểm tra venv đã kích hoạt**: Bạn sẽ thấy `(venv)` ở đầu dòng prompt.

#### Bước 2: Cài đặt dependencies (chỉ cần làm 1 lần)

```powershell
# Đảm bảo venv đã kích hoạt (sẽ thấy (venv) ở đầu)
pip install -r config/requirements.txt
```

#### Bước 3: Chạy ứng dụng

**⭐ Cách chạy: FastAPI (Khuyến nghị)**

```powershell
# Kích hoạt venv
.\venv\Scripts\Activate.ps1

# Chạy ứng dụng chính (kiến trúc mới)
uvicorn app.main:app --reload --host 0.0.0.0 --port 5000

# HOẶC chạy trực tiếp
python app/main.py
```

**💡 Giải thích lệnh:**

- `uvicorn` - ASGI server cho FastAPI (production-ready)
- `app.main:app` - Import app từ `app/main.py`
- `--reload` - Tự động reload khi code thay đổi (development)
- `--host 0.0.0.0` - Listen trên tất cả interfaces
- `--port 5000` - Port 5000

**⚠️ Lưu ý:**

- Bỏ `--reload` khi chạy production
- Thêm `--workers 4` cho production (xử lý nhiều requests)

#### Bước 4: Mở trình duyệt

**⚠️ Lưu ý quan trọng:**

- ✅ **Dùng một trong các URL sau**:
  - `http://localhost:5000`
  - `http://127.0.0.1:5000`

**Truy cập:**

- ✅ **Web UI**: http://localhost:5000
- ✅ **API Documentation (Swagger)**: http://localhost:5000/api/docs
- ✅ **ReDoc**: http://localhost:5000/api/redoc
- ✅ **Health Check**: http://localhost:5000/api/health

**⚠️ Lưu ý quan trọng:**

- ✅ **Dùng**: `http://localhost:5000` hoặc `http://127.0.0.1:5000`
- ❌ **KHÔNG dùng**: `http://0.0.0.0:5000` (sẽ báo lỗi ERR_ADDRESS_INVALID)

---

### 📋 Hướng dẫn chi tiết

#### ✅ Kiểm tra venv đã kích hoạt

Sau khi chạy `.\venv\Scripts\Activate.ps1`, bạn sẽ thấy:

```
(venv) PS D:\pbl6\SOURCE MalwareDetector\PBL6_DetectMalwareApplication-develop>
```

Có `(venv)` ở đầu nghĩa là đã kích hoạt thành công.

#### 🔧 Tạo venv mới (nếu chưa có)

```powershell
# Tạo venv
python -m venv venv

# Kích hoạt
.\venv\Scripts\Activate.ps1

# Cài dependencies
pip install -r config/requirements.txt
```

#### 🧪 Test YARA rules (tùy chọn)

```powershell
.\venv\Scripts\Activate.ps1
python scripts/check_yara_rules.py
```

#### 🛑 Dừng ứng dụng

Nhấn `Ctrl + C` trong terminal để dừng server.

#### 🔄 Tắt venv

```powershell
deactivate
```

---

### 📝 Ví dụ session hoàn chỉnh

```powershell
# 1. Chuyển vào thư mục dự án
cd "D:\pbl6\SOURCE MalwareDetector\PBL6_DetectMalwareApplication-develop"

# 2. Kích hoạt venv
.\venv\Scripts\Activate.ps1

# 3. (Nếu chưa cài) Cài dependencies
pip install -r config/requirements.txt

# 4. Chạy ứng dụng
# Option A: Flask (legacy)
python app/web_app.py

# Option B: FastAPI - Kiến trúc mới (khuyến nghị) ⭐
uvicorn app.main:app --reload --host 0.0.0.0 --port 5000
# HOẶC
python app/main.py

# Option C: Docker (nếu đã setup Docker)
cd config
docker-compose up -d

# 5. Mở browser: http://localhost:5000

# 6. Khi xong, nhấn Ctrl+C để dừng, sau đó:
deactivate
```

---

### ⚠️ Lưu ý quan trọng

1. **Luôn kích hoạt venv trước khi chạy**

   - Không kích hoạt venv → Lỗi `ModuleNotFoundError`
   - Kiểm tra: Phải thấy `(venv)` ở đầu prompt

2. **Chỉ cài dependencies trong venv**

   ```powershell
   # Đúng: Kích hoạt venv trước
   .\venv\Scripts\Activate.ps1
   pip install -r config/requirements.txt

   # Sai: Cài trực tiếp (sẽ cài vào Python system)
   pip install -r config/requirements.txt
   ```

3. **Port 5000 đã được dùng?**
   ```powershell
   # Đổi port (ví dụ 8080)
   uvicorn app.fastapi_app:app --reload --host 0.0.0.0 --port 8080
   ```

---

### Phương án 2: 🐳 Docker - Chạy trong Container

**Khi nào dùng:** Khi muốn test production-like environment hoặc deploy.

#### Yêu cầu:

- Docker đã cài đặt
- 2GB+ RAM
- 5GB+ dung lượng ổ cứng

#### Cách chạy:

##### Option A: Docker Build + Run

```bash
# 1. Vào thư mục dự án
cd PBL6_DetectMalwareApplication-develop

# 2. Build Docker image
docker build -f config/Dockerfile -t malware-detector .

# 3. Chạy container
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/yara_rules:/app/yara_rules \
  --name malware-detector \
  malware-detector

# 4. Xem logs
docker logs -f malware-detector

# 5. Truy cập: http://localhost:5000
```

##### Option B: Docker Compose (Khuyến nghị)

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

#### Quản lý Docker Container:

```bash
# Xem danh sách containers
docker ps

# Xem logs
docker logs malware-detector

# Dừng container
docker stop malware-detector

# Khởi động lại
docker start malware-detector

# Xóa container
docker rm malware-detector

# Xóa image
docker rmi malware-detector
```

#### Lưu ý khi dùng Docker:

- ✅ Tự động cài đặt tất cả dependencies
- ✅ Môi trường production-like
- ✅ Dễ deploy lên server
- ⚠️ Build lần đầu có thể mất vài phút
- ⚠️ Cần Docker đang chạy

---

### So sánh các phương án

| Phương án          | Tốc độ           | Dễ dùng       | Môi trường      | Khi nào dùng            |
| ------------------ | ---------------- | ------------- | --------------- | ----------------------- |
| **venv**           | ⭐⭐⭐ Rất nhanh | ⭐⭐⭐ Rất dễ | Development     | Phát triển, debug, test |
| **Docker**         | ⭐⭐ Trung bình  | ⭐⭐ Dễ       | Production-like | Test production, deploy |
| **Docker Compose** | ⭐⭐ Trung bình  | ⭐⭐⭐ Rất dễ | Production-like | Deploy, demo            |

---

## 🧪 Test hệ thống

```bash
python scripts/test_complete_system.py
```

## 📊 Tính năng

### Static Analysis:

- ✅ **564 YARA rules** từ Yara-Rules project (chính thức)
- ✅ **Hash-based detection** (SHA256, MD5, SHA1) với database malware
- ✅ **PE file analysis** (nếu có pefile) - imports, exports, entropy, packers
- ✅ **Strings extraction** - phát hiện suspicious strings
- ✅ **Web interface** dễ sử dụng
- ✅ **API endpoint** cho tích hợp (REST API)
- ✅ **Folder scanning** hỗ trợ quét nhiều file

### Framework:

- ✅ **Flask** - Ứng dụng gốc (đơn giản)
- ✅ **FastAPI** - Ứng dụng nâng cấp (async, auto docs, performance cao)

## 🔧 Scripts tiện ích

- `scripts/setup_yara.py`: Cài đặt và test YARA
- `scripts/fix_yara_rules.py`: Sửa lỗi YARA rules
- `scripts/test_complete_system.py`: Test toàn bộ hệ thống
- `scripts/check_rules.py`: Kiểm tra số lượng rules
- `scripts/simple_yara_check.py`: Kiểm tra đơn giản

## 📝 Sử dụng

1. Upload file đơn lẻ hoặc folder
2. Hệ thống sẽ quét với YARA rules và hash database
3. Xem kết quả chi tiết về malware detected
4. Download báo cáo phân tích

## 🛠️ Yêu cầu hệ thống

- Python 3.10+
- YARA engine
- 2GB+ RAM (cho YARA rules)
- Windows/Linux/macOS

## 📞 Hỗ trợ

- Xem `UPGRADE_PLAN.md` - Kế hoạch nâng cấp lên dynamic analysis
- Xem `scripts/README.md` - Hướng dẫn scripts
- Xem `yara_rules/rules/README.md` - Thông tin về YARA rules

## 📝 Lưu ý Quan Trọng

### ⭐ Entry Point Chính

- **Production/Development**: Dùng `app/main.py` - Kiến trúc chuẩn, đầy đủ tính năng
- **Legacy**: `app/web_app.py` (Flask) và `app/fastapi_app.py` (FastAPI cũ) - Có thể xóa

### 🔧 Development Tips

1. **Hot Reload**: Dùng `--reload` khi development để tự động reload code
2. **Debug Mode**: FastAPI có sẵn interactive API docs tại `/api/docs`
3. **Logs**: Xem logs trong terminal để debug
4. **Static Files**: CSS/JS ở `app/static/`, chỉnh sửa trực tiếp và refresh browser

### 📚 Tài liệu tham khảo

- `DEPLOYMENT.md` - Hướng dẫn deploy lên web (Docker, VPS, Cloud)
- `API_WEB_ARCHITECTURE.md` - Giải thích chi tiết về kiến trúc API + Web gộp chung

### 🗑️ Files có thể xóa

- `app/web_app.py` - Flask app (legacy)
- `app/fastapi_app.py` - FastAPI app (legacy)
- Các file chỉ để tham khảo nếu không dùng

## ⚠️ Troubleshooting

### Lỗi: ModuleNotFoundError

```powershell
# Đảm bảo venv đã kích hoạt
.\venv\Scripts\Activate.ps1
pip install -r config/requirements.txt
```

### Lỗi: Port 5000 đã được sử dụng

```powershell
# Đổi port (ví dụ 8080)
# FastAPI:
uvicorn app.fastapi_app:app --reload --host 0.0.0.0 --port 8080
```

### Lỗi: YARA rules không load

```powershell
python scripts/check_yara_rules.py
python scripts/fix_yara_rules.py
```
