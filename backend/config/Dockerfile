# Sử dụng image Python chính thức
FROM python:3.10-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt các gói hệ thống cần thiết
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    pkg-config \
    yara \
    # PostgreSQL client libraries (cho psycopg2-binary nếu cần)
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Cập nhật pip, setuptools, wheel
RUN pip install --upgrade pip setuptools wheel

# Sao chép requirements.txt trước để tận dụng cache
# Copy từ root của backend (context là .)
COPY requirements.txt .

# Cài đặt các thư viện Python
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn vào container (bao gồm ember/)
# Context là backend/ (từ docker-compose.yml: context: ..)
COPY . .

# Đảm bảo ember được copy - nếu không có thì copy riêng
RUN if [ ! -d "ember" ]; then \
        echo "[WARN] ember not found, trying to copy from explicit path..."; \
    fi

# Đảm bảo ember library có thể được import
# Kiểm tra xem ember có tồn tại không và liệt kê nội dung
RUN echo "[INFO] Checking ember library..." && \
    if [ -d "ember" ]; then \
        echo "[INFO] ember directory found"; \
        ls -la ember/ | head -10; \
        if [ -f "ember/__init__.py" ]; then \
            echo "[INFO] ember/__init__.py found"; \
        else \
            echo "[WARN] ember/__init__.py NOT found"; \
        fi; \
        if [ -f "ember/features.py" ]; then \
            echo "[INFO] ember/features.py found"; \
        else \
            echo "[WARN] ember/features.py NOT found"; \
        fi; \
    else \
        echo "[ERROR] ember directory NOT found in /app"; \
        echo "[ERROR] Listing /app contents:"; \
        ls -la /app | head -20; \
    fi

# Tạo thư mục uploads và logs
RUN mkdir -p uploads logs

# Expose port 5000 cho FastAPI
EXPOSE 5000

# Thiết lập biến môi trường production
ENV PYTHONUNBUFFERED=1
ENV ENV=production

# Chạy ứng dụng FastAPI với uvicorn (production server)
# Sử dụng app.main:app để tương thích với uvicorn
# Model file sẽ được normalize tự động khi load (đã có logic trong ember_model.py)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]
