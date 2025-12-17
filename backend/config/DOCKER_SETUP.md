# 🐳 Docker Setup Guide - Ubuntu

Hướng dẫn cấu hình và chạy Docker cho Backend trên Ubuntu.

## 📋 Yêu Cầu

- Docker Engine 20.10+
- Docker Compose 2.0+
- Ubuntu 20.04+ (hoặc Linux distribution tương tự)

## 🚀 Cài Đặt Docker (nếu chưa có)

```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine và Docker Compose
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

## ⚙️ Cấu Hình

### 1. Tạo file `.env` (tùy chọn)

Tạo file `.env` trong thư mục `backend/` nếu muốn override default values:

```bash
cd backend
cat > .env << EOF
# Database Configuration
DB_USER=sa
DB_PASSWORD=your_secure_password
DB_NAME=malwaredetection
DB_PORT=3306

# Backend Configuration
BACKEND_PORT=5000
ENV=production

# CORS Configuration - Cho phép frontend kết nối
# Thêm các origin của frontend (phân cách bằng dấu phẩy)
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173
EOF
```

**Lưu ý**: 
- File `.env` không bắt buộc vì đã có default values trong `docker-compose.yml`
- `CORS_ORIGINS` cần bao gồm URL của frontend để tránh lỗi CORS

### 2. Kiểm tra cấu trúc thư mục

Đảm bảo các thư mục sau tồn tại:

```
backend/
├── config/
│   ├── docker-compose.yml    # ← File này
│   ├── Dockerfile
│   └── DOCKER_SETUP.md       # ← File hướng dẫn này
├── requirements.txt
├── yara_rules/
│   └── rules/
│       └── index.yar
├── uploads/          # Sẽ tự động tạo
└── logs/             # Sẽ tự động tạo
```

## 🏃 Chạy Docker Compose

### Build và start services

**Quan trọng**: Chạy lệnh từ thư mục `backend/` (không phải `config/`):

```bash
cd backend
docker compose -f config/docker-compose.yml up -d --build
```

Hoặc tạo symlink để dùng ngắn gọn hơn:

```bash
cd backend
ln -s config/docker-compose.yml docker-compose.yml
docker compose up -d --build
```

### Xem logs

```bash
# Xem tất cả logs
docker compose -f config/docker-compose.yml logs -f

# Xem logs của backend
docker compose -f config/docker-compose.yml logs -f backend

# Xem logs của MySQL
docker compose -f config/docker-compose.yml logs -f mysql
```

### Kiểm tra status

```bash
docker compose -f config/docker-compose.yml ps
```

### Stop services

```bash
docker compose -f config/docker-compose.yml down
```

### Stop và xóa volumes (⚠️ Xóa dữ liệu)

```bash
docker compose -f config/docker-compose.yml down -v
```

## 🔍 Troubleshooting

### 1. Lỗi "Cannot connect to MySQL"

**Nguyên nhân**: MySQL chưa sẵn sàng khi backend start.

**Giải pháp**: 
- Kiểm tra healthcheck của MySQL: `docker compose -f config/docker-compose.yml logs mysql`
- Backend có `depends_on` với `condition: service_healthy`, nên sẽ đợi MySQL sẵn sàng
- Nếu vẫn lỗi, tăng `start_period` trong healthcheck

### 2. Lỗi "Permission denied" khi mount volumes

**Nguyên nhân**: Quyền truy cập thư mục trên host.

**Giải pháp**:
```bash
# Tạo thư mục với quyền phù hợp
cd backend
mkdir -p uploads logs
chmod 755 uploads logs
```

### 3. Lỗi "Port already in use"

**Nguyên nhân**: Port 5000 hoặc 3306 đã được sử dụng.

**Giải pháp**:
- Thay đổi port trong `.env` hoặc trực tiếp trong `docker-compose.yml`:
  ```env
  BACKEND_PORT=5001
  DB_PORT=3307
  ```
- Hoặc stop service đang dùng port:
  ```bash
  sudo lsof -i :5000
  sudo kill -9 <PID>
  ```

### 4. Lỗi "Module not found" trong container

**Nguyên nhân**: Requirements.txt không được copy đúng.

**Giải pháp**:
- Kiểm tra Dockerfile có copy `requirements.txt` đúng không
- Rebuild image: `docker compose -f config/docker-compose.yml build --no-cache backend`

### 5. Lỗi "YARA rules not found"

**Nguyên nhân**: YARA rules không được mount vào container.

**Giải pháp**:
- Kiểm tra volume mount trong `docker-compose.yml`
- Đảm bảo `yara_rules/rules/index.yar` tồn tại

### 6. Lỗi CORS khi frontend kết nối

**Nguyên nhân**: Frontend origin không được cho phép trong CORS config.

**Giải pháp**:
- Kiểm tra frontend đang chạy trên port nào (thường là 3000 hoặc 5173)
- Thêm origin vào `CORS_ORIGINS` trong `.env`:
  ```env
  CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://your-frontend-url:port
  ```
- Restart backend container: `docker compose -f config/docker-compose.yml restart backend`

### 7. Frontend không kết nối được với backend

**Nguyên nhân**: 
- Backend chưa expose port đúng
- Frontend đang gọi sai URL

**Giải pháp**:
- Kiểm tra backend port: `docker compose -f config/docker-compose.yml ps`
- Đảm bảo port mapping: `"${BACKEND_PORT:-5000}:5000"` trong docker-compose.yml
- Kiểm tra frontend API URL trong `frontend/src/constants/index.ts` hoặc `.env`
- Test backend từ terminal: `curl http://localhost:5000/api/health`

### 6. Lỗi "docker-compose.yml not found"

**Nguyên nhân**: Chạy lệnh từ sai thư mục.

**Giải pháp**:
- Đảm bảo đang ở thư mục `backend/`
- Sử dụng `-f config/docker-compose.yml` để chỉ định đường dẫn
- Hoặc tạo symlink: `ln -s config/docker-compose.yml docker-compose.yml`

## 📊 Kiểm Tra Health

### Backend Health Check

```bash
curl http://localhost:5000/api/health
```

### MySQL Connection Test

```bash
docker compose -f config/docker-compose.yml exec backend python -c "
import asyncio
from app.database.connection import init_database
asyncio.run(init_database())
print('✅ Database connection OK')
"
```

## 🔧 Các Lệnh Hữu Ích

```bash
# Rebuild chỉ backend service
docker compose -f config/docker-compose.yml build backend

# Restart một service
docker compose -f config/docker-compose.yml restart backend

# Xem resource usage
docker stats

# Vào container shell
docker compose -f config/docker-compose.yml exec backend bash

# Xem environment variables trong container
docker compose -f config/docker-compose.yml exec backend env

# Clean up (xóa containers, networks, volumes)
docker compose -f config/docker-compose.yml down -v --remove-orphans
```

## 📁 Cấu Trúc Files Docker

Tất cả files Docker config nằm trong `backend/config/`:

```
backend/config/
├── docker-compose.yml    # Docker Compose configuration (MySQL + Backend)
├── Dockerfile            # Backend Docker image definition
├── DOCKER_SETUP.md       # File hướng dẫn này
└── requirements_fix.txt  # Optional: Fixed requirements (nếu cần)
```

## 📝 Notes

1. **Volumes**: 
   - `uploads/` và `logs/` được mount từ host để persist data
   - `yara_rules/` được mount để có thể update rules mà không cần rebuild
   - `Malware.json` được mount để có thể update malware database

2. **Networks**: 
   - Services trong cùng network `malware-network` có thể communicate qua service name
   - Backend kết nối MySQL qua hostname `mysql`

3. **Health Checks**:
   - MySQL có healthcheck để đảm bảo sẵn sàng trước khi backend start
   - Backend có healthcheck để monitor service status

4. **Build Context**:
   - Build context là `..` (thư mục `backend/`) vì file `docker-compose.yml` nằm trong `config/`
   - Dockerfile path: `config/Dockerfile` (relative từ context)

5. **Production**:
   - Thay đổi passwords trong `.env` hoặc environment variables
   - Sử dụng secrets management (Docker secrets, Vault, etc.)
   - Enable SSL/TLS cho MySQL
   - Configure firewall rules
   - Sử dụng reverse proxy (nginx, traefik) cho production

## 🚀 Quick Start

```bash
# 1. Vào thư mục backend
cd backend

# 2. (Optional) Tạo symlink để dùng ngắn gọn
ln -s config/docker-compose.yml docker-compose.yml

# 3. Build và start
docker compose up -d --build

# 4. Xem logs
docker compose logs -f

# 5. Kiểm tra health
curl http://localhost:5000/api/health

# 6. (Optional) Cấu hình frontend
cd ../frontend
echo "VITE_API_URL=http://localhost:5000/api" > .env
npm run dev
```

## 🔗 Frontend Connection

### Cấu hình Frontend để kết nối với Backend Docker

1. **Tạo file `.env` trong `frontend/`**:
   ```env
   VITE_API_URL=http://localhost:5000/api
   ```

2. **Hoặc sử dụng default** (đã có trong `frontend/src/constants/index.ts`):
   - Frontend sẽ tự động dùng `http://localhost:5000/api` nếu không có `VITE_API_URL`

3. **Kiểm tra kết nối**:
   - Backend phải đang chạy: `docker compose -f config/docker-compose.yml ps`
   - Test từ browser console:
     ```javascript
     fetch('http://localhost:5000/api/health')
       .then(r => r.json())
       .then(console.log)
     ```

4. **Nếu gặp lỗi CORS**:
   - Thêm frontend URL vào `CORS_ORIGINS` trong backend `.env`
   - Restart backend: `docker compose -f config/docker-compose.yml restart backend`
```

