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

# Copy models trước (để tận dụng cache layer)
# Context là .. (backend/), nên models/ = backend/models/
COPY models/ models/

# Normalize line endings cho file model (CRLF -> LF) để tương thích với Linux
# LightGBM model files cần LF line endings trong Linux
# Sử dụng tr để xử lý file lớn tốt hơn sed
RUN if [ -f models/ember_model_2018.txt ]; then \
        echo "[INFO] Normalizing line endings for EMBER model file..."; \
        tr -d '\r' < models/ember_model_2018.txt > models/ember_model_2018.txt.tmp && \
        mv models/ember_model_2018.txt.tmp models/ember_model_2018.txt; \
        echo "[INFO] Line endings normalized successfully"; \
        # Kiểm tra file size để đảm bảo không bị corrupt
        FILE_SIZE=$(stat -c%s models/ember_model_2018.txt 2>/dev/null || stat -f%z models/ember_model_2018.txt 2>/dev/null || echo "0"); \
        if [ "$FILE_SIZE" -lt 1000000 ]; then \
            echo "[ERROR] Model file seems too small (${FILE_SIZE} bytes) - may be corrupted"; \
            exit 1; \
        fi; \
        echo "[INFO] Model file size: $((FILE_SIZE / 1024 / 1024)) MB"; \
    fi

# Sao chép toàn bộ mã nguồn vào container
COPY . .

# Tạo thư mục uploads và logs (models đã được copy ở trên)
RUN mkdir -p uploads logs

# Expose port 5000 cho FastAPI
EXPOSE 5000

# Thiết lập biến môi trường production
ENV PYTHONUNBUFFERED=1
ENV ENV=production

# Chạy ứng dụng FastAPI với uvicorn (production server)
# Sử dụng app.main:app để tương thích với uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]
