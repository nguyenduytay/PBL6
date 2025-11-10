# 📁 Cấu Trúc Dự Án - Tổ Chức Chuyên Nghiệp

## 🎯 Mục Tiêu

Dự án được tổ chức lại để:

- ✅ Dễ bảo trì và mở rộng
- ✅ Tách biệt frontend/backend rõ ràng
- ✅ Code sạch, dễ tái sử dụng
- ✅ Tuân thủ best practices

## 📂 Cấu Trúc Mới

```
PBL6_DetectMalwareApplication-develop/
│
├── 📦 app/                          # Backend Code (FastAPI)
│   ├── main.py                      # Entry point
│   ├── core/                        # Core Configuration
│   │   ├── config.py                # Settings, paths
│   │   └── dependencies.py          # Shared dependencies
│   ├── api/                         # API Layer
│   │   └── v1/
│   │       └── routes/              # API Endpoints
│   │           ├── scan.py
│   │           ├── health.py
│   │           ├── websocket.py
│   │           └── web.py
│   ├── services/                    # Business Logic
│   │   ├── analyzer_service.py
│   │   ├── yara_service.py
│   │   ├── hash_service.py
│   │   └── static_analyzer_service.py
│   └── schemas/                     # Pydantic Models
│
├── 📦 frontend/                     # Frontend Code
│   ├── templates/                  # HTML Templates
│   │   ├── base.html               # Base template
│   │   ├── components/             # Reusable components
│   │   │   ├── sidebar.html
│   │   │   ├── header.html
│   │   │   └── footer.html
│   │   └── pages/                  # Page templates
│   │       ├── dashboard.html
│   │       ├── submit.html
│   │       ├── analyses.html
│   │       └── analysis_detail.html
│   │
│   └── static/                     # Static Files
│       ├── css/
│       │   ├── main.css            # Main stylesheet (imports all)
│       │   ├── base.css            # Base styles
│       │   ├── components/         # Component styles
│       │   │   ├── cards.css
│       │   │   ├── tables.css
│       │   │   ├── forms.css
│       │   │   ├── buttons.css
│       │   │   ├── badges.css
│       │   │   ├── alerts.css
│       │   │   └── tabs.css
│       │   └── themes/             # Theme styles
│       │       └── cuckoo.css
│       │
│       └── js/
│           ├── main.js             # Main entry point
│           └── modules/            # JavaScript modules
│               ├── utils.js       # Utility functions
│               ├── charts.js       # Chart management
│               ├── upload.js       # File upload handling
│               └── api.js          # API client
│
├── 📦 src/                          # Core Analysis Engine
│   ├── Analysis/
│   ├── Database/
│   ├── Models/
│   └── Utils/
│
├── scripts/                         # Utility Scripts
├── yara_rules/                      # YARA Rules
└── uploads/                         # Upload Directory
```

## 🔄 Migration

Các file đã được di chuyển:

- ✅ Templates: `app/templates/` → `frontend/templates/pages/`
- ✅ Static files: `app/static/` → `frontend/static/`
- ✅ CSS được tách thành modules
- ✅ JS được tách thành modules
- ✅ Backend code giữ nguyên trong `app/` (không cần `backend/`)

## 📝 Sử Dụng

### Backend

#### Imports

```python
# Sử dụng app module
from app.core.config import settings
from app.services.analyzer_service import AnalyzerService
```

#### Chạy ứng dụng

```bash
# Cách 1: Sử dụng uvicorn
python -m uvicorn app.main:app --reload

# Cách 2: Chạy trực tiếp
python -m app.main
```

### Frontend

#### Templates

- Sử dụng `base.html` làm base template
- Components trong `templates/components/` có thể được include
- Pages trong `templates/pages/` là các trang chính

#### CSS

- Import `main.css` trong base template
- `main.css` tự động import tất cả modules
- Mỗi component có file CSS riêng trong `css/components/`

#### JavaScript

- `main.js` là entry point, import các modules
- Modules trong `js/modules/` có thể được import riêng
- Sử dụng ES6 modules (type="module")

## 🎨 Best Practices

1. **Tách biệt concerns**: Frontend và backend tách rõ ràng
2. **Component-based**: Tái sử dụng components
3. **Module-based**: Code được tổ chức thành modules nhỏ
4. **Consistent naming**: Đặt tên nhất quán
5. **Documentation**: Code được comment rõ ràng

## 🚀 Phát Triển Tiếp

1. Thêm components mới vào `frontend/templates/components/`
2. Thêm CSS modules vào `frontend/static/css/components/`
3. Thêm JS modules vào `frontend/static/js/modules/`
4. Thêm services mới vào `app/services/`
5. Cập nhật `main.css` và `main.js` để import modules mới
