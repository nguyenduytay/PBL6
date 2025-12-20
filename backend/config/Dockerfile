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
