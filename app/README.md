# 📦 Backend Application

## 📝 Giới Thiệu

Thư mục `app/` chứa **backend code** của dự án Malware Detector.

Mặc dù tên là `app`, nhưng đây chính là **backend** (FastAPI application).

## 📂 Cấu Trúc

```
app/
├── main.py              # Entry point - FastAPI application
├── core/                # Core Configuration
│   ├── config.py       # Settings, paths, YARA loading
│   └── dependencies.py # Shared dependencies (Jinja2, etc.)
├── api/                 # API Layer
│   └── v1/
│       └── routes/     # API Endpoints
│           ├── scan.py        # POST /api/scan
│           ├── health.py      # GET /api/health
│           ├── websocket.py   # WS /api/ws/{task_id}
│           └── web.py         # Web UI routes
├── services/           # Business Logic
│   ├── analyzer_service.py      # Main analysis service
│   ├── yara_service.py         # YARA scanning
│   ├── hash_service.py         # Hash detection
│   └── static_analyzer_service.py  # Static analysis
└── schemas/            # Pydantic Models
    └── scan.py         # ScanResult, AnalysisResult
```

## 🚀 Chạy Ứng Dụng

```bash
# Cách 1: Sử dụng uvicorn
python -m uvicorn app.main:app --reload

# Cách 2: Chạy trực tiếp
python -m app.main
```

## 📝 Lưu Ý

- Đây là **backend code**, không phải frontend
- Frontend code nằm trong thư mục `frontend/`
- Tên `app/` được giữ để tương thích với imports hiện tại
- Có thể đổi tên thành `backend/` trong tương lai nếu cần

## 🔗 Liên Kết

- Frontend: `../frontend/`
- Core Engine: `../src/`
- YARA Rules: `../yara_rules/`
