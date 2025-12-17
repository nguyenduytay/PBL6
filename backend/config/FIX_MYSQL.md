# 🔧 Fix MySQL Container Issues

## Vấn Đề

MySQL container gặp 2 lỗi:
1. **No space left on device** - Ổ cứng đầy
2. **Data directory has files in it** - Thư mục data đã có file nhưng MySQL đang cố initialize lại

## Giải Pháp

### Bước 1: Dừng và xóa containers/volumes cũ

```bash
cd backend

# Dừng tất cả containers
docker compose -f config/docker-compose.yml down

# Xóa MySQL volume (⚠️ MẤT DỮ LIỆU - chỉ làm nếu không cần data cũ)
docker volume rm backend_mysql_data
# Hoặc nếu tên volume khác:
docker volume ls | grep mysql
docker volume rm <volume_name>
```

### Bước 2: Dọn dẹp Docker (giải phóng dung lượng)

```bash
# Xóa containers đã dừng
docker container prune -f

# Xóa images không dùng
docker image prune -a -f

# Xóa volumes không dùng
docker volume prune -f

# Xóa tất cả (cẩn thận!)
docker system prune -a --volumes -f
```

### Bước 3: Kiểm tra dung lượng ổ cứng

```bash
# Kiểm tra dung lượng
df -h

# Kiểm tra Docker disk usage
docker system df
```

### Bước 4: Khởi động lại MySQL

```bash
cd backend

# Khởi động lại với volume mới
docker compose -f config/docker-compose.yml up -d mysql

# Xem logs
docker compose -f config/docker-compose.yml logs -f mysql
```

### Bước 5: Khởi động tất cả services

```bash
docker compose -f config/docker-compose.yml up -d
```

## Nếu Vẫn Gặp Lỗi "No space left on device"

### Giải pháp tạm thời: Giảm kích thước MySQL

Thêm vào `docker-compose.yml`:

```yaml
mysql:
  # ... existing config ...
  command: >
    --default-authentication-plugin=mysql_native_password
    --innodb-buffer-pool-size=128M
    --max-connections=50
```

### Hoặc: Sử dụng MySQL nhẹ hơn

Thay `mysql:8.0` bằng `mysql:8.0-debian` (nhẹ hơn) hoặc `mariadb:latest`

## Kiểm Tra Sau Khi Fix

```bash
# Kiểm tra containers đang chạy
docker compose -f config/docker-compose.yml ps

# Kiểm tra MySQL health
docker compose -f config/docker-compose.yml exec mysql mysqladmin ping -h localhost -uroot -p123456

# Kiểm tra backend health
curl http://localhost:5000/api/health
```

