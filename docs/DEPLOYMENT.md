# 🚀 Hướng Dẫn Deploy Dự Án Lên Web

Dự án này **HOÀN TOÀN CÓ THỂ** deploy lên web. Đây là hướng dẫn chi tiết các phương án deploy.

## ✅ Các phương án deploy

### 1. **Docker (Khuyến nghị - Dễ nhất)**

Deploy bằng Docker trên VPS, Cloud Server, hoặc bất kỳ server nào có Docker.

#### Yêu cầu:

- Docker và Docker Compose đã cài đặt
- Server/VPS có ít nhất 2GB RAM
- 5GB+ dung lượng ổ cứng (cho YARA rules và uploads)

#### Cách deploy:

```bash
# 1. Clone/nhập dự án vào server
cd PBL6_DetectMalwareApplication-develop

# 2. Chạy Docker Compose
cd config
docker-compose up -d

# 3. Kiểm tra logs
docker-compose logs -f

# 4. Truy cập ứng dụng
# http://your-server-ip:5000
```

#### Dừng/khởi động lại:

```bash
docker-compose stop      # Dừng
docker-compose start     # Khởi động lại
docker-compose down      # Dừng và xóa container
docker-compose restart   # Khởi động lại
```

---

### 2. **VPS/Cloud Server (Ubuntu/Debian)**

Deploy trực tiếp lên VPS mà không dùng Docker.

#### Yêu cầu:

- Ubuntu 20.04+ hoặc Debian 11+
- Python 3.10+
- Nginx (reverse proxy)
- Supervisor hoặc systemd (quản lý process)

#### Các bước:

##### Bước 1: Chuẩn bị server

```bash
# Cập nhật hệ thống
sudo apt update && sudo apt upgrade -y

# Cài đặt Python và dependencies
sudo apt install -y python3.10 python3.10-venv python3-pip nginx supervisor

# Cài đặt YARA
sudo apt install -y yara
```

##### Bước 2: Upload dự án lên server

```bash
# Sử dụng Git hoặc SCP/SFTP
git clone <your-repo> /var/www/malware-detector
cd /var/www/malware-detector
```

##### Bước 3: Setup Python environment

```bash
# Tạo virtual environment
python3.10 -m venv venv
source venv/bin/activate

# Cài đặt dependencies
pip install --upgrade pip
pip install -r config/requirements.txt
```

##### Bước 4: Cấu hình Nginx (Reverse Proxy)

Tạo file `/etc/nginx/sites-available/malware-detector`:

```nginx
server {
    listen 80;
    server_name your-domain.com;  # Hoặc IP của server

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (cho tương lai)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (tùy chọn - có thể để FastAPI xử lý)
    location /static/ {
        alias /var/www/malware-detector/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Kích hoạt:

```bash
sudo ln -s /etc/nginx/sites-available/malware-detector /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

##### Bước 5: Cấu hình Supervisor (Quản lý process)

Tạo file `/etc/supervisor/conf.d/malware-detector.conf`:

```ini
[program:malware-detector]
directory=/var/www/malware-detector
command=/var/www/malware-detector/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 5000 --workers 4
user=www-data
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/malware-detector.log
environment=ENV=production
```

Khởi động:

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start malware-detector
sudo supervisorctl status
```

##### Bước 6: SSL/HTTPS (Tùy chọn - Khuyến nghị)

```bash
# Cài đặt Certbot
sudo apt install certbot python3-certbot-nginx

# Cấu hình SSL
sudo certbot --nginx -d your-domain.com
```

---

### 3. **Platform-as-a-Service (PaaS)**

#### A. **Heroku**

1. Tạo file `Procfile` trong root:

```
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 2
```

2. Deploy:

```bash
heroku create malware-detector-app
git push heroku main
```

#### B. **Railway**

1. Kết nối GitHub repository
2. Chọn Python environment
3. Set build command: `pip install -r config/requirements.txt`
4. Set start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

#### C. **Render**

1. Tạo Web Service mới
2. Connect GitHub repo
3. Build command: `pip install -r config/requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

---

### 4. **Cloud Providers**

#### A. **AWS (EC2 + Elastic Beanstalk)**

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p python-3.10 malware-detector

# Create and deploy
eb create malware-detector-env
eb deploy
```

#### B. **Google Cloud Platform (Cloud Run)**

```bash
# Build và push image
gcloud builds submit --tag gcr.io/PROJECT_ID/malware-detector

# Deploy
gcloud run deploy malware-detector \
  --image gcr.io/PROJECT_ID/malware-detector \
  --platform managed \
  --region asia-southeast1 \
  --allow-unauthenticated
```

#### C. **Azure (App Service)**

1. Tạo App Service trong Azure Portal
2. Deploy từ GitHub hoặc Docker
3. Set startup command: `uvicorn app.main:app --host 0.0.0.0 --port 8000`

---

## 🔧 Cấu hình Production

### Environment Variables

Tạo file `.env` (hoặc set trong Docker/systemd):

```bash
ENV=production
HOST=0.0.0.0
PORT=5000
PYTHONUNBUFFERED=1
```

### Tối ưu Performance

1. **Workers**: Tăng số workers cho uvicorn:

```bash
uvicorn app.main:app --workers 4 --host 0.0.0.0 --port 5000
```

2. **Static Files**: Dùng Nginx serve static files thay vì FastAPI

3. **Caching**: Thêm caching cho static files

### Bảo mật

1. ✅ **HTTPS**: Luôn dùng HTTPS trong production
2. ✅ **Rate Limiting**: Thêm rate limiting cho API
3. ✅ **File Size Limits**: Giới hạn kích thước file upload
4. ✅ **Input Validation**: Validate tất cả inputs

---

## 📊 So sánh các phương án

| Phương án         | Độ khó          | Chi phí           | Performance    | Khuyến nghị        |
| ----------------- | --------------- | ----------------- | -------------- | ------------------ |
| **Docker**        | ⭐ Dễ           | 💰💰 Trung bình   | ⭐⭐⭐ Tốt     | ✅ **Khuyến nghị** |
| **VPS + Nginx**   | ⭐⭐ Trung bình | 💰 Rẻ             | ⭐⭐⭐ Rất tốt | ✅ **Khuyến nghị** |
| **Heroku**        | ⭐ Dễ           | 💰💰💰 Đắt        | ⭐⭐ Ổn        | ❌ Hạn chế         |
| **Railway**       | ⭐ Dễ           | 💰💰💰 Trung bình | ⭐⭐⭐ Tốt     | ✅ Tốt             |
| **AWS/GCP/Azure** | ⭐⭐⭐ Khó      | 💰💰💰 Đắt        | ⭐⭐⭐ Rất tốt | ✅ Enterprise      |

---

## ✅ Checklist trước khi deploy

- [ ] Đã test local thành công
- [ ] YARA rules đã được load đúng
- [ ] Static files (CSS/JS) hoạt động
- [ ] Upload folder có quyền ghi
- [ ] Database connection (nếu có) đã cấu hình
- [ ] Environment variables đã set
- [ ] Firewall đã mở port 5000 (hoặc 80/443)
- [ ] SSL/HTTPS đã cấu hình (cho production)
- [ ] Logs đã được cấu hình
- [ ] Backup strategy đã có

---

## 🐛 Troubleshooting

### Lỗi: YARA rules không load

```bash
# Kiểm tra YARA đã cài chưa
which yara
yara --version

# Kiểm tra file rules tồn tại
ls -la yara_rules/rules/index.yar
```

### Lỗi: Port đã được sử dụng

```bash
# Tìm process đang dùng port 5000
sudo lsof -i :5000
# Hoặc
sudo netstat -tulpn | grep 5000

# Kill process nếu cần
sudo kill -9 <PID>
```

### Lỗi: Permission denied

```bash
# Fix permissions cho uploads
sudo chown -R www-data:www-data /var/www/malware-detector/uploads
sudo chmod -R 755 /var/www/malware-detector/uploads
```

---

## 📞 Hỗ trợ

Nếu gặp vấn đề khi deploy, kiểm tra:

1. Logs: `docker-compose logs` hoặc `supervisorctl tail -f malware-detector`
2. Health check: `curl http://localhost:5000/api/health`
3. Application logs trong `/var/log/` hoặc `logs/` folder

---

**Chúc bạn deploy thành công! 🎉**
