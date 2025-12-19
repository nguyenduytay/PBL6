# 🏗️ Kiến Trúc Backend - Simplified Architecture

## 📁 Cấu Trúc Thư Mục

```
backend/
├── app/
│   ├── main.py                    # Application entry point
│   ├── core/                      # Core layer - Configuration & Database
│   │   ├── config.py             # Application settings (YARA, DB, CORS, etc.)
│   │   ├── database.py           # Database connection & initialization
│   │   ├── security.py           # Authentication & JWT
│   │   ├── dependencies.py       # FastAPI dependency injection
│   │   └── logging.py            # Logging configuration
│   ├── models/                    # Data Models (Dataclasses)
│   │   └── analysis.py           # Analysis & YaraMatch models
│   ├── schemas/                   # Pydantic Schemas (Validation)
│   │   ├── analysis.py           # Analysis request/response schemas
│   │   └── scan.py               # Scan request/response schemas
│   ├── services/                  # Business Logic & Data Access
│   │   ├── analysis_service.py   # Analysis CRUD & search
│   │   ├── analyzer_service.py   # Malware analysis orchestration
│   │   ├── yara_service.py       # YARA scanning
│   │   ├── hash_service.py       # Hash calculation
│   │   └── static_analyzer_service.py  # PE analysis
│   ├── api/v1/                    # API Routes
│   │   ├── __init__.py           # Router registration
│   │   └── routes/               # Endpoint definitions
│   │       ├── scan.py           # POST /api/scan
│   │       ├── analyses.py       # GET /api/analyses
│   │       ├── search.py         # GET /api/search/analyses
│   │       ├── export.py         # GET /api/export/analyses
│   │       ├── batch_scan.py     # POST /api/scan/batch
│   │       ├── health.py         # GET /api/health
│   │       └── websocket.py      # WebSocket /api/ws
│   └── shared/                    # Shared Utilities
│       ├── exceptions.py         # Custom exceptions
│       ├── utils.py              # Helper functions
│       └── constants.py          # Application constants
├── config/                        # Configuration files
├── logs/                          # Application logs
├── uploads/                       # Uploaded files storage
├── yara_rules/                    # YARA rules
├── requirements.txt               # Python dependencies
└── .env                          # Environment variables
```

---

## 🔄 Luồng Xử Lý API Request

### 1️⃣ **Scan File Endpoint** - `POST /api/scan`

```
┌─────────────┐
│   Client    │ Upload file
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  main.py - FastAPI Application                              │
│  • CORS middleware                                           │
│  • Request logging                                           │
│  • Route to /api/scan                                        │
└──────┬──────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  api/v1/routes/scan.py                                       │
│  • Validate file upload (size, type)                         │
│  • Save file to uploads/                                     │
│  • Call AnalyzerService.analyze_and_save()                   │
└──────┬──────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  services/analyzer_service.py                                │
│  AnalyzerService.analyze_and_save()                          │
│  1. Calculate file hash (SHA256, MD5)                        │
│  2. Check hash in database (HashService)                     │
│  3. Scan with YARA rules (YaraService)                       │
│  4. Analyze PE structure (StaticAnalyzerService)             │
│  5. Aggregate results                                        │
│  6. Save to database (AnalysisService)                       │
└──────┬──────────────────────────────────────────────────────┘
       │
       ├──────────────────────────────────────────────────────┐
       │                                                        │
       ▼                                                        ▼
┌──────────────────┐                              ┌────────────────────┐
│  YaraService     │                              │  HashService       │
│  • Load rules    │                              │  • Calculate SHA256│
│  • Scan file     │                              │  • Calculate MD5   │
│  • Return matches│                              └────────────────────┘
└──────────────────┘                                         │
       │                                                      │
       ▼                                                      ▼
┌──────────────────────────────────────────────────────────────┐
│  services/analysis_service.py                                │
│  AnalysisService.create()                                    │
│  • Insert into analyses table                                │
│  • Insert YARA matches into yara_matches table               │
│  • Return analysis_id                                        │
└──────┬───────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  core/database.py                                             │
│  • get_db_connection() - Get MySQL pool                       │
│  • Execute SQL INSERT                                         │
│  • Commit transaction                                         │
└──────┬───────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  MySQL Database                                               │
│  Tables: analyses, yara_matches, ratings                      │
└──────┬───────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  Response to Client                                           │
│  {                                                            │
│    "id": 123,                                                 │
│    "filename": "malware.exe",                                 │
│    "sha256": "abc123...",                                     │
│    "malware_detected": true,                                  │
│    "yara_matches": [...],                                     │
│    "analysis_time": 1.23                                      │
│  }                                                            │
└───────────────────────────────────────────────────────────────┘
```

---

### 2️⃣ **Get Analyses List** - `GET /api/analyses`

```
Client Request
    │
    ▼
api/v1/routes/analyses.py
    │ • Validate query params (limit, offset)
    │ • Call AnalysisService.get_all()
    ▼
services/analysis_service.py
    │ • Query database with pagination
    │ • Parse JSON fields (yara_matches, pe_info)
    ▼
core/database.py
    │ • Execute SELECT query
    │ • Return rows
    ▼
Response: { items: [...], total: 490, limit: 20, offset: 0 }
```

---

### 3️⃣ **Search Analyses** - `GET /api/search/analyses?q=malware`

```
Client Request
    │
    ▼
api/v1/routes/search.py
    │ • Validate search query
    │ • Call AnalysisService.search()
    ▼
services/analysis_service.py
    │ • Search by filename, SHA256, MD5 using LIKE
    │ • Count total results
    ▼
core/database.py
    │ • Execute SELECT with WHERE ... LIKE '%query%'
    ▼
Response: { items: [...], total: 5, query: "malware" }
```

---

### 4️⃣ **Get Statistics** - `GET /api/analyses/stats/summary`

```
Client Request
    │
    ▼
api/v1/routes/analyses.py
    │ • Call AnalysisService.get_statistics()
    ▼
services/analysis_service.py
    │ • Count total analyses
    │ • Count malware detected
    │ • Count recent (24h)
    ▼
core/database.py
    │ • Execute multiple COUNT queries
    ▼
Response: {
    total_analyses: 490,
    malware_detected: 2,
    clean_files: 488,
    recent_24h: 490
}
```

---

## 🎯 Các Layer và Trách Nhiệm

### **1. API Layer** (`app/api/v1/routes/`)
- **Trách nhiệm:**
  - Nhận HTTP requests
  - Validate input (Pydantic schemas)
  - Gọi Services
  - Trả về HTTP responses
- **Không làm:**
  - Business logic
  - Database access trực tiếp

### **2. Service Layer** (`app/services/`)
- **Trách nhiệm:**
  - Business logic
  - Orchestrate multiple operations
  - Data access (CRUD operations)
  - Transaction management
- **Ví dụ:**
  - `AnalysisService`: CRUD cho analyses
  - `AnalyzerService`: Orchestrate malware analysis
  - `YaraService`: YARA scanning logic

### **3. Models** (`app/models/`)
- **Trách nhiệm:**
  - Define data structures (dataclasses)
  - Business logic methods (e.g., `is_malware()`)
- **Không làm:**
  - Database operations
  - API handling

### **4. Schemas** (`app/schemas/`)
- **Trách nhiệm:**
  - Input validation (Pydantic)
  - Request/Response serialization
  - Data transformation
- **Ví dụ:**
  - `AnalysisCreate`: Validate scan request
  - `AnalysisResponse`: Format response

### **5. Core** (`app/core/`)
- **Trách nhiệm:**
  - Configuration management
  - Database connection pooling
  - Security (JWT, CORS)
  - Logging setup

---

## 📊 Database Schema

```sql
-- Analyses table
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
    INDEX idx_created_at (created_at)
);

-- YARA matches table
CREATE TABLE yara_matches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    analysis_id INT NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    tags TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

-- Ratings table
CREATE TABLE ratings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    analysis_id INT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    reviewer_name VARCHAR(100),
    tags JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
```

---

## 🔧 Startup Process

```
1. main.py loads
   │
   ├─> Load environment variables (.env)
   │
   ├─> Initialize settings (core/config.py)
   │   ├─> Load YARA rules
   │   ├─> Setup CORS origins
   │   └─> Configure logging
   │
   ├─> Initialize database (core/database.py)
   │   ├─> Create database if not exists
   │   ├─> Create connection pool
   │   └─> Create tables if not exists
   │
   ├─> Register API routers (api/v1/__init__.py)
   │   ├─> /scan
   │   ├─> /analyses
   │   ├─> /search
   │   ├─> /export
   │   └─> /health
   │
   └─> Start uvicorn server (0.0.0.0:5000)
```

---

## 🚀 Key Features

### **1. Malware Analysis**
- YARA rule scanning
- PE file analysis
- Hash-based detection
- Suspicious string extraction

### **2. Data Management**
- Full CRUD operations
- Advanced search (filename, SHA256, MD5)
- Statistics & reporting
- Export (CSV, JSON, Excel)

### **3. Performance**
- Connection pooling (aiomysql)
- Async/await throughout
- Background tasks for batch scanning
- Efficient JSON storage

### **4. Security**
- File size limits (2GB default)
- CORS protection
- Input validation (Pydantic)
- SQL injection prevention (parameterized queries)

---

## 📝 API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Upload and scan file |
| `GET` | `/api/analyses` | List all analyses (paginated) |
| `GET` | `/api/analyses/{id}` | Get analysis by ID |
| `GET` | `/api/analyses/sha256/{sha256}` | Get analysis by SHA256 |
| `GET` | `/api/analyses/stats/summary` | Get statistics |
| `DELETE` | `/api/analyses/{id}` | Delete analysis |
| `GET` | `/api/search/analyses?q=query` | Search analyses |
| `GET` | `/api/export/analyses/csv` | Export to CSV |
| `GET` | `/api/export/analyses/json` | Export to JSON |
| `GET` | `/api/export/analyses/excel` | Export to Excel |
| `POST` | `/api/scan/batch` | Batch scan (ZIP/TAR) |
| `GET` | `/api/health` | Health check |

---

## 🔍 Example: Complete Request Flow

**Request:** `POST /api/scan` (Upload malware.exe)

1. **Client** uploads file via HTTP POST
2. **main.py** receives request, applies CORS middleware
3. **scan.py** validates file (size < 2GB)
4. **scan.py** saves file to `uploads/malware.exe`
5. **AnalyzerService** starts analysis:
   - **HashService** calculates SHA256 & MD5
   - **YaraService** scans with 500+ YARA rules
   - **StaticAnalyzerService** analyzes PE structure
6. **AnalyzerService** aggregates results
7. **AnalysisService** saves to database:
   - INSERT into `analyses` table
   - INSERT into `yara_matches` table
8. **Database** commits transaction, returns ID
9. **scan.py** formats response (Pydantic schema)
10. **Client** receives JSON response with analysis results

**Total time:** ~1-3 seconds (depending on file size)

---

## 🎓 Design Principles

1. **Simplicity** - Clear folder structure, easy to navigate
2. **Separation of Concerns** - Each layer has specific responsibility
3. **Async First** - All I/O operations are async
4. **Type Safety** - Pydantic schemas for validation
5. **Testability** - Services are independent and testable
6. **Scalability** - Connection pooling, background tasks

---

## 🔄 Migration Notes

**From:** Clean Architecture (domain/application/infrastructure)  
**To:** Simplified Architecture (models/schemas/services)

**Changes:**
- ✅ Removed complex layer separation
- ✅ Consolidated repository logic into services
- ✅ Simplified dependency injection
- ✅ Reduced boilerplate code
- ✅ Improved code readability

**Benefits:**
- Faster development
- Easier onboarding
- Less abstraction overhead
- More maintainable codebase