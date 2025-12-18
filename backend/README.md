# 🚀 Backend - Malware Detector API

Backend API cho hệ thống phát hiện malware sử dụng **FastAPI** (Python) với **Layered Architecture**.

## 📖 Giới Thiệu Dự Án

### Mục Đích

Hệ thống **Malware Detector** là một nền tảng phân tích mã độc tự động, sử dụng các kỹ thuật phân tích tĩnh (static analysis) để phát hiện malware trong các file executable, script, và các file đáng ngờ khác.

### Các Tính Năng Chính

1. **Phân Tích Tĩnh (Static Analysis)**:
   - Quét YARA rules (564+ rules từ Yara-Rules project)
   - Phân tích hash (SHA256, MD5, SHA1) và so sánh với malware database
   - Phân tích PE file (Windows executables) - sections, imports, exports, entropy
   - Trích xuất suspicious strings
   - Phân tích capabilities (Capa tool - nếu có)

2. **Quản Lý Lịch Sử Phân Tích**:
   - Lưu trữ kết quả phân tích vào MySQL database
   - Tìm kiếm và lọc analyses
   - Export dữ liệu (CSV, JSON, Excel)
   - Xóa và quản lý analyses

3. **Batch Processing**:
   - Quét nhiều file cùng lúc (folder hoặc archive)
   - Theo dõi tiến trình quét
   - Xử lý bất đồng bộ (async)

4. **Rating System**:
   - Đánh giá chất lượng phân tích (1-5 sao)
   - Comment và tags
   - Thống kê ratings

### Kiến Trúc

Hệ thống sử dụng **Layered Architecture** để tách biệt concerns và dễ maintain:

- **API Layer**: Nhận HTTP requests, validate input, trả về responses
- **Application Layer**: Orchestrate các use cases, xử lý business logic phức tạp
- **Domain Layer**: Business rules, domain models, repository interfaces
- **Infrastructure Layer**: Database connections, external services, repository implementations
- **Core Layer**: Configuration, security, logging, dependencies

## 📋 Yêu Cầu

- Python 3.10+
- MySQL (tùy chọn - để lưu lịch sử phân tích)
- YARA engine (tự động cài với dependencies)

## 🏗️ Cấu Trúc Dự Án (Layered Architecture)

```
backend/
│
├── 📦 app/                           # FastAPI Application
│   ├── main.py                       # ⭐ Entry point chính
│   │
│   ├── 🎯 core/                      # Core Layer - Configuration & Infrastructure
│   │   ├── config.py                # Application settings (Pydantic-based)
│   │   ├── security.py              # JWT, password hashing, RBAC
│   │   ├── dependencies.py          # Dependency Injection
│   │   └── logging.py               # Structured logging & audit
│   │
│   ├── 🌐 api/                       # API Layer - Presentation
│   │   └── v1/
│   │       ├── router.py            # Tổng hợp routers
│   │       ├── endpoints/           # API endpoints (mới)
│   │       │   └── analyses.py      # Analysis endpoints với DI
│   │       └── routes/              # Legacy routes (đang migration)
│   │           ├── scan.py         # POST /api/scan - Quét file
│   │           ├── analyses.py     # GET /api/analyses - Lịch sử phân tích
│   │           ├── batch_scan.py    # POST /api/scan/batch - Batch scan
│   │           ├── health.py       # GET /api/health - Health check
│   │           ├── ratings.py       # POST /api/ratings - Rating system
│   │           ├── search.py       # GET /api/search - Search analyses
│   │           ├── export.py       # GET /api/export - Export data
│   │           └── websocket.py    # WS /api/ws/{task_id} - Real-time
│   │
│   ├── 🏛️ domain/                    # Domain Layer - Business Logic
│   │   └── analyses/
│   │       ├── models.py           # Domain models (business entities)
│   │       ├── schemas.py          # Pydantic schemas (validation)
│   │       ├── services.py         # Business logic services
│   │       └── repositories.py     # Repository interfaces (abstractions)
│   │
│   ├── 🎬 application/              # Application Layer - Use Cases
│   │   └── use_cases/
│   │       ├── get_analysis.py     # Get analysis use case
│   │       └── get_analyses_list.py # Get analyses list use case
│   │
│   ├── 🔧 infrastructure/            # Infrastructure Layer - External Concerns
│   │   ├── database.py             # Database connection management
│   │   └── repositories/           # Repository implementations
│   │       └── analysis_repository.py # Analysis repository implementation
│   │
│   ├── 🔗 shared/                   # Shared Utilities
│   │   ├── exceptions.py           # Custom exceptions
│   │   ├── utils.py                # Utility functions
│   │   └── constants.py            # Application constants
│   │
│   ├── ⚙️ services/                  # Legacy Services (đang migration)
│   │   ├── analyzer_service.py      # Orchestrator chính
│   │   ├── yara_service.py          # YARA scanning
│   │   ├── hash_service.py          # Hash detection
│   │   └── static_analyzer_service.py # PE analysis
│   │
│   ├── 🗄️ database/                 # Legacy Database (đang migration)
│   │   ├── connection.py            # MySQL connection pool
│   │   ├── analysis_repository.py   # CRUD operations (legacy)
│   │   ├── rating_repository.py     # Rating CRUD
│   │   └── ml_schema.py             # ML tables schema
│   │
│   ├── 📋 schemas/                  # Legacy Schemas (đang migration)
│   │   └── scan.py                  # Data validation schemas
│   │
│   └── 📊 models/                    # Legacy Models (đang migration)
│       └── analysis.py              # Analysis model
│
├── 🔧 src/                           # Legacy Core Modules (VẪN CẦN THIẾT)
│   ├── Analysis/
│   │   └── StaticAnalyzer.py        # PE file analysis (được import trong config)
│   ├── Database/
│   │   ├── Driver.py                # MySQL driver
│   │   └── Malware.py               # Hash database (được import trong hash_service)
│   ├── Models/
│   │   └── Malware.py               # Malware models
│   └── Utils/
│       └── Utils.py                 # Utilities (được import trong hash_service)
│
├── 🛡️ yara_rules/                   # YARA Rules Database
│   └── rules/
│       └── index.yar                # 564+ YARA rules
│
├── 📁 uploads/                       # Upload folder (temporary files)
├── 📁 logs/                          # Log files (tự động tạo)
├── 📝 scripts/                       # Utility scripts
├── 🐳 config/                        # Docker configuration
│   ├── docker-compose.yml           # Docker Compose (MySQL + Backend)
│   ├── Dockerfile                    # Backend Docker image
│   └── DOCKER_SETUP.md               # Docker setup guide
│
├── 📚 ARCHITECTURE.md                # Kiến trúc chi tiết
├── requirements.txt                  # Python dependencies
└── venv/                             # Virtual environment (optional)
```

### 📐 Kiến Trúc Layered

```
┌─────────────────────────────────────────────────────────┐
│                    API Layer (Presentation)              │
│  - HTTP endpoints, Request/Response handling             │
│  - FastAPI routers, Dependencies injection              │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│              Application Layer (Use Cases)              │
│  - Orchestration, Use case implementations              │
│  - Event handling, Side effects                         │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│                Domain Layer (Business Logic)            │
│  - Domain models, Business rules                        │
│  - Domain services, Repository interfaces               │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│            Infrastructure Layer (External)              │
│  - Database, Storage, External APIs                     │
│  - Repository implementations                           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  Core & Shared                          │
│  - Configuration, Security, Logging                      │
│  - Utilities, Exceptions, Constants                     │
└─────────────────────────────────────────────────────────┘
```

### 🔄 Luồng Xử Lý Request

```
1. Request đến API Layer
   ↓
2. API Layer (endpoints) → gọi Use Cases
   ↓
3. Application Layer (use cases) → gọi Domain Services
   ↓
4. Domain Layer (services) → gọi Repository Interfaces
   ↓
5. Infrastructure Layer (repository implementations) → truy cập Database
   ↓
6. Response quay ngược lại qua các layers
```

**Ví dụ cụ thể:**
```
GET /api/analyses/1
  ↓
API: get_analysis() endpoint
  ↓
Use Case: GetAnalysisUseCase.execute()
  ↓
Domain Service: AnalysisService.get_analysis_by_id()
  ↓
Repository Interface: IAnalysisRepository.get_by_id()
  ↓
Repository Implementation: AnalysisRepository.get_by_id() → MySQL query
  ↓
Response: AnalysisResponse → JSON
```

---

## 🔄 Luồng Chạy Toàn Bộ Hệ Thống (Từ Đầu Đến Cuối)

### 📥 Luồng Upload và Phân Tích File

```
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 1: CLIENT UPLOAD FILE                                  │
└─────────────────────────────────────────────────────────────┘
Client (Browser/Frontend)
  ↓ POST /api/scan
  Content-Type: multipart/form-data
  Body: file=<binary data>
  ↓
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 2: API LAYER - Nhận Request                           │
└─────────────────────────────────────────────────────────────┘
FastAPI Application (app/main.py)
  ↓
CORS Middleware → Kiểm tra origin
  ↓
API Router (app/api/v1/router.py)
  ↓
Scan Endpoint (app/api/v1/routes/scan.py)
  ↓
@router.post("")
async def scan_file(file: UploadFile)
  ↓
Lưu file tạm: uploads/<filename>
  ↓
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 3: APPLICATION LAYER - Orchestration                  │
└─────────────────────────────────────────────────────────────┘
AnalyzerService.analyze_and_save(filepath, filename)
  ↓
├─→ BƯỚC 3.1: Phân tích file
│   analyze_single_file(filepath)
│   ↓
│   ├─→ HashService.check_hash(filepath)
│   │   ├─→ Tính SHA256 của file
│   │   ├─→ So sánh với malware database (Malware.json)
│   │   └─→ Trả về matches nếu có
│   │
│   ├─→ YaraService.scan_file(filepath)  ← YARA SCANNING
│   │   ├─→ Lấy YARA rules đã compile
│   │   ├─→ rules.match(filepath)  ← YARA Engine quét file
│   │   └─→ Trả về YARA matches
│   │
│   └─→ StaticAnalyzerService.analyze_file(filepath)
│       ├─→ Phân tích PE file (nếu là PE)
│       ├─→ Trích xuất strings
│       └─→ Phân tích capabilities (Capa)
│
└─→ BƯỚC 3.2: Lưu kết quả
    ├─→ Xác định malware_detected = True/False
    ├─→ Chuẩn bị analysis_data
    └─→ AnalysisRepository.create(analysis_data)
        ↓
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 4: INFRASTRUCTURE LAYER - Database                     │
└─────────────────────────────────────────────────────────────┘
AnalysisRepository.create()
  ↓
MySQL Connection (aiomysql)
  ↓
INSERT INTO analyses (filename, sha256, malware_detected, ...)
  ↓
INSERT INTO yara_matches (analysis_id, rule_name, ...)
  ↓
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 5: RESPONSE - Trả Về Kết Quả                          │
└─────────────────────────────────────────────────────────────┘
AnalysisRepository.create() → analysis_id
  ↓
AnalyzerService.analyze_and_save() → analysis_data
  ↓
Scan Endpoint → ScanResult (Pydantic model)
  ↓
FastAPI → JSON Response
  ↓
Client nhận kết quả:
{
  "filename": "test.exe",
  "sha256": "abc123...",
  "malware_detected": true,
  "yara_matches": [...],
  "pe_info": {...},
  "analysis_time": 2.5
}
  ↓
┌─────────────────────────────────────────────────────────────┐
│ BƯỚC 6: CLEANUP                                             │
└─────────────────────────────────────────────────────────────┘
Xóa file tạm: os.remove(filepath)
```

### 🔍 Chi Tiết Bước 3.1: YARA Scanning (Quan Trọng Nhất)

```
YaraService.scan_file(filepath)
  ↓
┌─────────────────────────────────────────────────────────────┐
│ 3.1.1: Lấy YARA Rules Đã Compile                            │
└─────────────────────────────────────────────────────────────┘
settings.get_yara_rules()
  ↓
Global variable: yara_rules (đã compile ở startup)
  ↓
yara.Rules object chứa 564+ rules
  ↓
┌─────────────────────────────────────────────────────────────┐
│ 3.1.2: YARA Engine Quét File                                │
└─────────────────────────────────────────────────────────────┘
rules.match(filepath)
  ↓
YARA Engine (yara-python library):
  ├─→ Mở file từ disk
  ├─→ Đọc file byte-by-byte
  ├─→ Với mỗi rule trong 564+ rules:
  │   ├─→ Tìm strings patterns trong file
  │   ├─→ Tìm hex patterns trong file
  │   ├─→ Tìm regex patterns trong file
  │   ├─→ Kiểm tra condition (logic: AND, OR, NOT)
  │   └─→ Nếu condition = True → Rule MATCH
  └─→ Trả về list các rules đã match
  ↓
┌─────────────────────────────────────────────────────────────┐
│ 3.1.3: Xử Lý Matches                                        │
└─────────────────────────────────────────────────────────────┘
Với mỗi match:
  ├─→ Extract rule name
  ├─→ Extract tags
  ├─→ Extract metadata (description, author)
  ├─→ Extract matched strings (vị trí, giá trị)
  └─→ Format thành Dict
  ↓
Trả về: List[Dict] với thông tin matches
```

### 📊 Ví Dụ Cụ Thể: Phân Tích File `trojan.exe`

**Input**: File `trojan.exe` (PE file, 50KB)

**Quá trình**:

1. **Upload**: Client upload `trojan.exe` → Lưu vào `uploads/trojan.exe`

2. **Hash Check**:
   ```python
   sha256 = calculate_sha256("uploads/trojan.exe")
   # Result: "a1b2c3d4e5f6..."
   # Check trong Malware.json → Không tìm thấy
   ```

3. **YARA Scan**:
   ```python
   rules = settings.get_yara_rules()  # 564+ rules đã compile
   matches = rules.match("uploads/trojan.exe")
   # YARA Engine quét file:
   # - Đọc 50KB file
   # - So khớp với 564+ rules
   # - Tìm thấy:
   #   * Rule "Trojan_Generic" MATCH (tìm thấy "cmd.exe" + "powershell")
   #   * Rule "Packer_UPX" MATCH (tìm thấy UPX signature)
   # Result: [Match(rule="Trojan_Generic"), Match(rule="Packer_UPX")]
   ```

4. **PE Analysis**:
   ```python
   pe_info = analyze_pe("uploads/trojan.exe")
   # Result: {
   #   "sections": [...],
   #   "imports": ["kernel32.dll", "user32.dll"],
   #   "suspicious_features": ["High entropy section"]
   # }
   ```

5. **Kết Quả**:
   ```json
   {
     "filename": "trojan.exe",
     "sha256": "a1b2c3d4...",
     "malware_detected": true,
     "yara_matches": [
       {
         "rule": "Trojan_Generic",
         "tags": ["trojan"],
         "description": "Generic trojan detection"
       },
       {
         "rule": "Packer_UPX",
         "tags": ["packer"],
         "description": "UPX packer detected"
       }
     ],
     "pe_info": {...},
     "analysis_time": 1.2
   }
   ```

6. **Lưu Database**:
   ```sql
   INSERT INTO analyses (filename, sha256, malware_detected, ...)
   INSERT INTO yara_matches (analysis_id, rule_name, ...)
   ```

---

## 🎯 Logic Quyết Định: Làm Sao Biết File Có Malware Hay Không?

### 📋 Tổng Quan

Hệ thống sử dụng **3 phương pháp phân tích** để phát hiện malware, và quyết định `malware_detected = True/False` dựa trên kết quả của các phương pháp này.

### 🔍 3 Phương Pháp Phân Tích

#### 1️⃣ **Hash-Based Detection** (Phát Hiện Dựa Trên Hash)

**Cách hoạt động:**
- Tính SHA256 hash của file
- So sánh với malware database (file `Malware.json`)
- Nếu hash khớp → File đã được biết là malware

**Code thực tế:**
```python
# File: app/services/hash_service.py
sha256 = sha256_hash(filepath)  # Tính SHA256
malwares = await get_malware_by_list_sha256([sha256])  # Tìm trong database

if malwares:
    # File có trong malware database → malware_detected = True
    results.append({
        "type": "hash",  # ← Quan trọng: type = "hash"
        "sha256": malware.sha256,
        "malwareType": malware.malwareType,
        "infoUrl": f"https://bazaar.abuse.ch/sample/{sha256}/"
    })
```

**Kết quả:**
- Nếu tìm thấy → `result["type"] = "hash"` → **malware_detected = True**
- Nếu không tìm thấy → Không có result → Tiếp tục kiểm tra YARA

---

#### 2️⃣ **YARA Scanning** (Phát Hiện Dựa Trên Pattern Matching)

**Cách hoạt động:**
- Quét file với 564+ YARA rules
- Mỗi rule tìm kiếm patterns đặc trưng của malware (strings, hex patterns, regex)
- Nếu bất kỳ rule nào match → File có dấu hiệu malware

**Code thực tế:**
```python
# File: app/services/yara_service.py
matches = self.rules.match(filepath)  # YARA Engine quét file

if matches:
    # Có rule match → malware_detected = True
    results.append({
        "type": "yara",  # ← Quan trọng: type = "yara"
        "matches": ", ".join(match_details),
        "rule_count": len(matches)
    })
```

**Kết quả:**
- Nếu có match → `result["type"] = "yara"` → **malware_detected = True**
- Nếu không có match → Không có result → File có thể sạch

---

#### 3️⃣ **Static Analysis** (Phân Tích Tĩnh - PE, Strings, Capabilities)

**Cách hoạt động:**
- Phân tích cấu trúc PE file (nếu là Windows executable)
- Trích xuất suspicious strings
- Phân tích capabilities (network, file system, registry access)
- **Lưu ý**: Static analysis chỉ cung cấp thông tin bổ sung, **KHÔNG quyết định** malware_detected

**Code thực tế:**
```python
# File: app/services/static_analyzer_service.py
static_analysis = self.static_analyzer_service.analyze_file(filepath)
# Trả về: {
#     "hashes": {"sha256": ..., "md5": ...},
#     "yara_matches": [...],  # Chi tiết YARA matches (chỉ để lưu DB)
#     "pe_info": {...},
#     "strings": [...],
#     "capabilities": [...]
# }
```

**Lưu ý quan trọng:**
- StaticAnalyzer **CŨNG chạy YARA scan** (dòng 62 trong `StaticAnalyzer.py`), nhưng:
  - YARA scan trong StaticAnalyzer chỉ để lấy **thông tin chi tiết** (rule names, strings, metadata)
  - **KHÔNG ảnh hưởng** đến quyết định `malware_detected`
  - Chỉ dùng để lưu vào database (`yara_matches` field)

**Kết quả:**
- Chỉ cung cấp thông tin chi tiết về file (PE info, strings, capabilities)
- YARA matches từ StaticAnalyzer chỉ để lưu vào database, **KHÔNG dùng để quyết định** malware_detected
- Quyết định `malware_detected` chỉ dựa trên `YaraService.scan_file()` và `HashService.check_hash()`

---

### ⚖️ Logic Quyết Định `malware_detected`

**Code quyết định:**
```python
# File: app/services/analyzer_service.py - analyze_and_save()

# BƯỚC 1: Thu thập kết quả từ các phương pháp
results = await self.analyze_single_file(filepath)
# analyze_single_file() chạy:
#   1. HashService.check_hash() → results với type="hash" (nếu match)
#   2. YaraService.scan_file() → results với type="yara" (nếu match)
#   3. Nếu không có gì → results với type="clean"
# 
# results = [
#     {"type": "hash", ...},      # Nếu hash match
#     {"type": "yara", ...},      # Nếu YARA match
#     {"type": "clean", ...}      # Nếu không phát hiện gì
# ]

# BƯỚC 2: LOGIC QUYẾT ĐỊNH (dòng 88-91)
malware_detected = any(
    result.get("type") in ["hash", "yara"] 
    for result in results
)

# BƯỚC 3: Static Analysis (chỉ để lấy thông tin chi tiết, KHÔNG ảnh hưởng malware_detected)
static_analysis = self.analyze_with_static_analyzer(filepath)
# StaticAnalyzer cũng chạy YARA scan, nhưng chỉ để lấy chi tiết matches
# → Lưu vào database, KHÔNG dùng để quyết định malware_detected
```

**Giải thích:**
- `malware_detected = True` **NẾU**:
  - ✅ Có bất kỳ result nào có `type == "hash"` (hash match với malware database)
  - ✅ **HOẶC** có bất kỳ result nào có `type == "yara"` (YARA rule match)
  
- `malware_detected = False` **NẾU**:
  - ❌ Không có result nào có `type == "hash"`
  - ❌ **VÀ** không có result nào có `type == "yara"`
  - ✅ Chỉ có result có `type == "clean"` hoặc không có result nào

---

### 📊 Ví Dụ Cụ Thể

#### **Ví Dụ 1: File Malware (Hash Match)**

**Input**: File `trojan.exe` có SHA256 đã có trong malware database

**Quá trình phân tích:**
1. **Hash Check**: 
   ```python
   sha256 = "a1b2c3d4e5f6..."  # Hash của file
   malwares = get_malware_by_list_sha256([sha256])
   # → Tìm thấy trong database
   results = [{"type": "hash", "malwareType": "Trojan", ...}]
   ```

2. **YARA Scan**: 
   ```python
   matches = rules.match(filepath)
   # → Không có match (file đã được pack/obfuscate)
   ```

3. **Quyết định**:
   ```python
   malware_detected = any(result["type"] in ["hash", "yara"] for result in results)
   # → malware_detected = True (vì có result["type"] == "hash")
   ```

**Kết quả**: `malware_detected = True` ✅

---

#### **Ví Dụ 2: File Malware (YARA Match)**

**Input**: File `suspicious.exe` chứa patterns đặc trưng của malware

**Quá trình phân tích:**
1. **Hash Check**: 
   ```python
   sha256 = "x1y2z3..."  # Hash mới, chưa có trong database
   malwares = get_malware_by_list_sha256([sha256])
   # → Không tìm thấy
   ```

2. **YARA Scan**: 
   ```python
   matches = rules.match(filepath)
   # → Match với rule "Trojan_Generic" (tìm thấy "cmd.exe" + "powershell")
   results = [{"type": "yara", "matches": "Trojan_Generic", ...}]
   ```

3. **Quyết định**:
   ```python
   malware_detected = any(result["type"] in ["hash", "yara"] for result in results)
   # → malware_detected = True (vì có result["type"] == "yara")
   ```

**Kết quả**: `malware_detected = True` ✅

---

#### **Ví Dụ 3: File Sạch (Clean File)**

**Input**: File `notepad.exe` (file Windows hợp lệ)

**Quá trình phân tích:**
1. **Hash Check**: 
   ```python
   sha256 = "abc123..."
   malwares = get_malware_by_list_sha256([sha256])
   # → Không tìm thấy
   ```

2. **YARA Scan**: 
   ```python
   matches = rules.match(filepath)
   # → Không có match (file không có patterns đáng ngờ)
   ```

3. **Quyết định**:
   ```python
   results = []  # Không có result nào
   malware_detected = any(result["type"] in ["hash", "yara"] for result in results)
   # → malware_detected = False (vì không có result nào)
   ```

**Kết quả**: `malware_detected = False` ✅

---

#### **Ví Dụ 4: File Có Cả Hash Và YARA Match**

**Input**: File `known_malware.exe` vừa có trong database, vừa match YARA rules

**Quá trình phân tích:**
1. **Hash Check**: 
   ```python
   results = [{"type": "hash", ...}]  # Hash match
   ```

2. **YARA Scan**: 
   ```python
   results.append({"type": "yara", ...})  # YARA match
   ```

3. **Quyết định**:
   ```python
   malware_detected = any(result["type"] in ["hash", "yara"] for result in results)
   # → malware_detected = True (có cả hash và yara match)
   ```

**Kết quả**: `malware_detected = True` ✅

---

### 🎯 Tóm Tắt Logic Quyết Định

```
┌─────────────────────────────────────────────────────────┐
│              QUYẾT ĐỊNH malware_detected                 │
└─────────────────────────────────────────────────────────┘

File Upload
    ↓
┌─────────────────────────────────────────────────────────┐
│ BƯỚC 1: Hash Check                                      │
│   ├─→ Tính SHA256                                       │
│   ├─→ So sánh với malware database                      │
│   └─→ Nếu match → result["type"] = "hash"              │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ BƯỚC 2: YARA Scan                                       │
│   ├─→ Quét với 564+ YARA rules                          │
│   ├─→ Tìm patterns đặc trưng                           │
│   └─→ Nếu match → result["type"] = "yara"              │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ BƯỚC 3: Quyết Định                                      │
│                                                          │
│   malware_detected = any(                               │
│       result["type"] in ["hash", "yara"]                │
│       for result in results                             │
│   )                                                      │
│                                                          │
│   ┌──────────────────────────────────────┐              │
│   │ Nếu có result["type"] == "hash"     │              │
│   │ HOẶC result["type"] == "yara"       │              │
│   │ → malware_detected = True ✅         │              │
│   └──────────────────────────────────────┘              │
│                                                          │
│   ┌──────────────────────────────────────┐              │
│   │ Nếu KHÔNG có "hash" VÀ "yara"       │              │
│   │ → malware_detected = False ✅        │              │
│   └──────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────┘
```

### ⚠️ Lưu Ý Quan Trọng

1. **Hash Detection là chính xác nhất**: Nếu hash match với database → File chắc chắn là malware đã biết
2. **YARA Detection có thể có false positive**: Một số file hợp lệ có thể match với YARA rules (ví dụ: file packer, obfuscator)
3. **Static Analysis không quyết định**: PE info, strings, capabilities chỉ cung cấp thông tin bổ sung, không ảnh hưởng đến `malware_detected`
4. **Kết hợp nhiều phương pháp**: Hệ thống sử dụng cả hash và YARA để tăng độ chính xác

---

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
# Windows venv local - để frontend có thể kết nối
HOST=127.0.0.1
PORT=5000

# Database
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=malwaredetection

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173
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

Xem hướng dẫn chi tiết trong [`config/DOCKER_SETUP.md`](config/DOCKER_SETUP.md)

**Quick Start**:

```bash
cd backend
docker compose -f config/docker-compose.yml up -d --build
```

Hoặc tạo symlink để dùng ngắn gọn:

```bash
cd backend
ln -s config/docker-compose.yml docker-compose.yml
docker compose up -d --build
```

**Kiểm tra**:
```bash
# Xem logs
docker compose -f config/docker-compose.yml logs -f

# Health check
curl http://localhost:5000/api/health
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

## 🛡️ YARA Rules - Cơ Chế Phân Tích Mã Độc

### 📍 Vị Trí và Cấu Trúc

```
yara_rules/
└── rules/
    ├── index.yar              # File chính chứa 564+ YARA rules
    ├── malware/               # Rules phát hiện malware
    ├── cve_rules/             # Rules phát hiện CVE exploits
    ├── packers/               # Rules phát hiện packers/obfuscators
    ├── webshells/             # Rules phát hiện webshells
    └── ...                    # Các categories khác
```

### 🔍 YARA Là Gì?

**YARA** (Yet Another Recursive Acronym) là một công cụ pattern matching mạnh mẽ được thiết kế để giúp các nhà nghiên cứu malware phát hiện và phân loại các mẫu malware.

**Nguyên lý hoạt động**:
- YARA sử dụng **pattern matching** dựa trên:
  - **Strings**: Chuỗi ký tự đặc trưng của malware
  - **Hex patterns**: Byte patterns trong binary
  - **Regular expressions**: Pattern phức tạp
  - **Conditions**: Điều kiện logic kết hợp các patterns

### 📝 Cấu Trúc YARA Rule

Một YARA rule có cấu trúc như sau:

```yara
rule RuleName {
    meta:
        description = "Mô tả rule"
        author = "Tác giả"
        date = "2024-01-01"
    
    strings:
        $string1 = "suspicious_string" ascii
        $string2 = { E8 00 00 00 00 }  // Hex pattern
        $regex1 = /cmd\.exe/i          // Regular expression
    
    condition:
        $string1 and ($string2 or $regex1)
}
```

**Giải thích**:
- **meta**: Metadata mô tả rule
- **strings**: Các patterns cần tìm (strings, hex, regex)
- **condition**: Điều kiện để rule match (ví dụ: tìm thấy string1 VÀ (string2 HOẶC regex1))

### 🔄 Luồng Phân Tích YARA Trong Hệ Thống

#### Bước 1: Khởi Tạo - Load YARA Rules

```
Application Startup (app/main.py)
  ↓
startup_event()
  ↓
settings.load_yara_rules()
  ↓
File: app/core/config.py - load_yara_rules()
  ↓
yara.compile(filepath="yara_rules/rules/index.yar")
  ↓
YARA Engine compile tất cả rules thành compiled rules object
  ↓
Lưu vào global variable: yara_rules
```

**Code thực tế**:
```python
# File: app/core/config.py
@classmethod
def load_yara_rules(cls) -> Optional[yara.Rules]:
    global yara_rules
    if yara_rules is not None:
        return yara_rules  # Đã load rồi, return ngay
    
    # Compile YARA rules từ file
    yara_rules = yara.compile(filepath=str(settings.YARA_RULES_PATH))
    # yara_rules giờ là một compiled rules object chứa 564+ rules
    return yara_rules
```

**Kết quả**: Một `yara.Rules` object chứa tất cả 564+ rules đã được compile sẵn, sẵn sàng để scan.

---

#### Bước 2: Nhận File Upload

```
Client upload file qua POST /api/scan
  ↓
FastAPI nhận UploadFile
  ↓
Lưu file tạm vào uploads/ folder
  ↓
File: app/api/v1/routes/scan.py
```

**Code thực tế**:
```python
# File: app/api/v1/routes/scan.py
@router.post("")
async def scan_file(file: UploadFile = File(...)):
    # Lưu file tạm
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)
    
    # Gọi phân tích
    analysis_data = await analyzer_service.analyze_and_save(str(filepath), file.filename)
```

---

#### Bước 3: Phân Tích File - Gọi YARA Service

```
analyzer_service.analyze_and_save()
  ↓
analyze_single_file(filepath)
  ↓
yara_service.scan_file(filepath)
```

**Code thực tế**:
```python
# File: app/services/analyzer_service.py
async def analyze_single_file(self, filepath: str):
    # ... hash checking ...
    
    # 3) YARA scan
    yara_results = self.yara_service.scan_file(filepath)
    results.extend(yara_results)
```

---

#### Bước 4: YARA Service - Quét File Với Rules

```
YaraService.scan_file(filepath)
  ↓
File: app/services/yara_service.py
  ↓
self.rules.match(filepath)  # ← ĐÂY LÀ BƯỚC QUAN TRỌNG
```

**Code thực tế**:
```python
# File: app/services/yara_service.py
def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
    if not self.rules:
        return []  # Chưa load rules
    
    # YARA Engine quét file với tất cả rules đã compile
    matches = self.rules.match(filepath)
    # matches là list các rule đã match
    
    # Xử lý kết quả
    results = []
    for match in matches:
        # match.rule: Tên rule đã match
        # match.tags: Tags của rule
        # match.meta: Metadata (description, author, etc.)
        # match.strings: Các strings đã match trong file
        results.append({
            "type": "yara",
            "rule": match.rule,
            "tags": list(match.tags),
            "description": match.meta.get('description', ''),
            "strings": [str(s) for s in match.strings]
        })
    
    return results
```

---

#### Bước 5: YARA Engine - Quá Trình So Khớp (Matching)

**Đây là bước quan trọng nhất - YARA Engine làm gì bên trong:**

```
rules.match(filepath)
  ↓
YARA Engine (yara-python library)
  ↓
1. Đọc file từ disk (filepath)
  ↓
2. Đọc từng byte trong file
  ↓
3. Với mỗi rule trong 564+ rules:
   ├─→ Kiểm tra strings section:
   │   ├─→ Tìm $string1 trong file
   │   ├─→ Tìm $string2 (hex pattern) trong file
   │   └─→ Tìm $regex1 trong file
   │
   ├─→ Kiểm tra condition:
   │   ├─→ Nếu condition = "$string1 and $string2"
   │   ├─→ Phải tìm thấy CẢ $string1 VÀ $string2
   │   └─→ Nếu đúng → Rule MATCH
   │
   └─→ Nếu match → Thêm vào results
  ↓
4. Trả về tất cả rules đã match
```

**Ví dụ cụ thể:**

Giả sử có rule:
```yara
rule Trojan_Generic {
    strings:
        $s1 = "cmd.exe" ascii
        $s2 = "powershell" ascii
        $s3 = { 4D 5A }  // MZ header (PE file)
    
    condition:
        $s1 and $s2 and $s3
}
```

**Quá trình scan file `malware.exe`:**

1. YARA đọc file `malware.exe`
2. Tìm kiếm:
   - ✅ Tìm thấy `"cmd.exe"` ở offset 0x1234
   - ✅ Tìm thấy `"powershell"` ở offset 0x5678
   - ✅ Tìm thấy bytes `4D 5A` ở đầu file (PE header)
3. Kiểm tra condition: `$s1 and $s2 and $s3` → **TRUE**
4. Rule `Trojan_Generic` **MATCH** → Thêm vào results

**Kết quả**:
```json
{
  "type": "yara",
  "rule": "Trojan_Generic",
  "tags": ["trojan", "generic"],
  "description": "Generic trojan detection",
  "strings": [
    {"offset": 0x1234, "value": "cmd.exe"},
    {"offset": 0x5678, "value": "powershell"},
    {"offset": 0x0000, "value": "MZ"}
  ]
}
```

---

#### Bước 6: Xử Lý Kết Quả và Lưu Database

```
YARA matches
  ↓
YaraService.scan_file() → List[Dict]
  ↓
AnalyzerService.analyze_single_file() → List[Dict]
  ↓
AnalyzerService.analyze_and_save()
  ↓
Xác định malware_detected = True (nếu có YARA match)
  ↓
Lưu vào database:
  - analyses table: filename, sha256, malware_detected, yara_matches (JSON)
  - yara_matches table: analysis_id, rule_name, tags, description
  ↓
Trả về kết quả cho client
```

**Code thực tế**:
```python
# File: app/services/analyzer_service.py
async def analyze_and_save(self, filepath: str, filename: str):
    # Phân tích
    results = await self.analyze_single_file(filepath)
    static_analysis = self.analyze_with_static_analyzer(filepath)
    
    # Xác định có malware không
    malware_detected = any(
        result.get("type") in ["hash", "yara"] 
        for result in results
    )
    
    # Lưu vào database
    analysis_data = {
        'filename': filename,
        'sha256': sha256,
        'malware_detected': malware_detected,
        'yara_matches': static_analysis.get("yara_matches", []),  # JSON
        # ...
    }
    
    analysis_id = await self.analysis_repo.create(analysis_data)
    return analysis_data
```

---

### 🎯 Tóm Tắt Luồng YARA Phân Tích

```
1. STARTUP: Compile YARA rules (564+ rules) → yara.Rules object
   ↓
2. UPLOAD: Client upload file → Lưu tạm vào uploads/
   ↓
3. SCAN: Gọi yara_service.scan_file(filepath)
   ↓
4. MATCH: YARA Engine quét file với tất cả rules
   ├─→ Đọc file byte-by-byte
   ├─→ So khớp với strings/hex/regex patterns
   ├─→ Kiểm tra conditions
   └─→ Trả về matches
   ↓
5. PROCESS: Xử lý matches → Format kết quả
   ↓
6. SAVE: Lưu vào database (analyses + yara_matches tables)
   ↓
7. RESPONSE: Trả về JSON cho client
```

### 📊 Ví Dụ Kết Quả YARA Match

**Input**: File `trojan.exe` chứa:
- String `"cmd.exe"` ở offset 0x1000
- String `"powershell"` ở offset 0x2000
- PE header `MZ` ở đầu file

**YARA Rules Match**:
```json
{
  "yara_matches": [
    {
      "rule": "Trojan_Generic",
      "tags": ["trojan", "generic"],
      "meta": {
        "description": "Generic trojan detection rule"
      },
      "strings": [
        {
          "identifier": "$s1",
          "offset": 4096,
          "value": "cmd.exe"
        },
        {
          "identifier": "$s2",
          "offset": 8192,
          "value": "powershell"
        }
      ]
    }
  ],
  "malware_detected": true
}
```

### 🔧 Các Loại YARA Rules Trong Hệ Thống

1. **Malware Rules** (`yara_rules/rules/malware/`):
   - Phát hiện các loại malware cụ thể (Trojan, Ransomware, Backdoor, etc.)

2. **CVE Rules** (`yara_rules/rules/cve_rules/`):
   - Phát hiện exploits cho các CVE (Common Vulnerabilities and Exposures)

3. **Packer Rules** (`yara_rules/rules/packers/`):
   - Phát hiện các packer/obfuscator (UPX, VMProtect, etc.)

4. **Webshell Rules** (`yara_rules/rules/webshells/`):
   - Phát hiện webshells (PHP, ASP, JSP backdoors)

5. **Capabilities Rules** (`yara_rules/rules/capabilities/`):
   - Phát hiện các capabilities (network, file system, registry, etc.)

### 📚 Nguồn YARA Rules

- **Repository**: https://github.com/Yara-Rules/rules.git
- **Số lượng**: 564+ rules (tự động cập nhật)
- **Vị trí**: `yara_rules/rules/index.yar`

### 🔄 Cập Nhật Rules

```bash
cd yara_rules
git pull origin main
# Restart backend để load rules mới
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
- **Architecture**: Layered Architecture (Core, Domain, Application, Infrastructure, API)
- **Server**: Uvicorn (ASGI)
- **Database**: MySQL (tùy chọn)
- **Port**: 5000
- **API Base URL**: http://localhost:5000/api

### 📚 Tài Liệu Kiến Trúc

Xem thêm chi tiết về kiến trúc trong file [`ARCHITECTURE.md`](./ARCHITECTURE.md)

**Chúc bạn sử dụng thành công! 🚀**

