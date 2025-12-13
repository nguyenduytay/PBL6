# 🏗️ Kiến Trúc Layered Architecture cho FastAPI

## 📁 Cấu Trúc Thư Mục

```
backend/
├── app/
│   ├── main.py                    # Application entry point
│   ├── core/                      # Core layer - Configuration, Security, Dependencies
│   │   ├── config.py             # Application configuration
│   │   ├── security.py           # Authentication, Authorization, JWT
│   │   ├── dependencies.py       # Dependency Injection
│   │   └── logging.py            # Logging và monitoring
│   ├── api/                       # API layer - Presentation
│   │   └── v1/
│   │       ├── router.py         # Tổng hợp routers
│   │       └── endpoints/         # API endpoints
│   │           ├── analyses.py
│   │           ├── scan.py
│   │           └── ...
│   ├── domain/                    # Domain layer - Business Logic
│   │   ├── analyses/
│   │   │   ├── models.py         # Domain models
│   │   │   ├── schemas.py        # Pydantic schemas
│   │   │   ├── services.py       # Business logic services
│   │   │   └── repositories.py   # Repository interfaces
│   │   └── ratings/
│   ├── application/               # Application layer - Use Cases
│   │   └── use_cases/
│   │       ├── scan_file.py
│   │       ├── get_analysis.py
│   │       └── ...
│   ├── infrastructure/            # Infrastructure layer - External concerns
│   │   ├── database.py           # Database connection
│   │   ├── storage.py            # File storage
│   │   └── repositories/         # Repository implementations
│   │       ├── analysis_repository.py
│   │       └── ...
│   └── shared/                    # Shared utilities
│       ├── exceptions.py        # Custom exceptions
│       ├── utils.py              # Utility functions
│       └── constants.py          # Constants
├── tests/
└── requirements.txt
```

## 🔄 Luồng Xử Lý Request

```
Request → API Layer → Application Layer → Domain Layer → Infrastructure Layer
                ↓
         Response ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ←
```

## 📝 Các Layer

### 1. Core Layer (`app/core/`)
- **config.py**: Cấu hình ứng dụng, environment variables
- **security.py**: JWT, password hashing, RBAC
- **dependencies.py**: Dependency Injection cho FastAPI
- **logging.py**: Structured logging và audit logging

### 2. API Layer (`app/api/`)
- **endpoints/**: API endpoints, request/response handling
- **router.py**: Tổng hợp tất cả routers

### 3. Domain Layer (`app/domain/`)
- **models.py**: Domain models (business entities)
- **schemas.py**: Pydantic schemas cho validation
- **services.py**: Business logic services
- **repositories.py**: Repository interfaces (abstractions)

### 4. Application Layer (`app/application/`)
- **use_cases/**: Use case implementations (orchestration)

### 5. Infrastructure Layer (`app/infrastructure/`)
- **database.py**: Database connection management
- **storage.py**: File storage management
- **repositories/**: Repository implementations

### 6. Shared (`app/shared/`)
- **exceptions.py**: Custom exceptions
- **utils.py**: Utility functions
- **constants.py**: Application constants

## 🔐 Security Best Practices

1. **JWT Authentication**: Sử dụng `JWTBearer` từ `core.security`
2. **Password Hashing**: Sử dụng `hash_password()` và `verify_password()`
3. **Input Sanitization**: Sử dụng `sanitize_input()` từ `core.security`
4. **Role-Based Access**: Sử dụng `require_role()` decorator

## 📊 Logging

- Sử dụng `get_logger()` từ `core.logging`
- Audit logging với `log_audit()`
- Request logging với `log_request()`
- Error logging với `log_error()`

## 🧪 Testing Strategy

- **Unit Tests**: Test từng layer riêng biệt
- **Integration Tests**: Test interaction giữa các layers
- **E2E Tests**: Test toàn bộ flow

## 📚 Best Practices

1. **Separation of Concerns**: Mỗi layer chỉ lo một việc
2. **Dependency Injection**: Sử dụng FastAPI Depends()
3. **Error Handling**: Sử dụng custom exceptions từ `shared.exceptions`
4. **Documentation**: Comment đầy đủ cho mỗi function
5. **Type Hints**: Sử dụng type hints cho tất cả functions

