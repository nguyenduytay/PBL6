# Hướng Dẫn Cài Đặt Hỗ Trợ RAR

## Vấn Đề

Khi upload file RAR, bạn có thể gặp lỗi:
```
RAR support not available. Please install rarfile: pip install rarfile
```

## Giải Pháp

### 1. Cài Đặt rarfile (Python Package)

#### Môi trường Local (Windows/Linux/macOS)

```bash
# Vào thư mục backend
cd backend

# Kích hoạt virtual environment (nếu có)
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Cài đặt rarfile
pip install rarfile==4.1
```

Hoặc cài đặt từ requirements.txt:
```bash
pip install -r requirements.txt
```

#### Docker

Nếu chạy bằng Docker, `rarfile` sẽ tự động được cài đặt từ `requirements.txt` khi build image.

### 2. Cài Đặt unrar Binary (Bắt Buộc)

`rarfile` Python package **cần** unrar binary để hoạt động. Bạn phải cài đặt unrar trên hệ thống:

#### Windows

**Cách 1: Cài đặt WinRAR**
- Tải và cài đặt WinRAR từ: https://www.winrar.com/
- WinRAR sẽ cài đặt `unrar.exe` vào hệ thống

**Cách 2: Chỉ cài đặt unrar**
- Tải unrar từ: https://www.rarlab.com/rar_add.htm
- Giải nén và thêm vào PATH

#### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install unrar
```

#### Linux (CentOS/RHEL)

```bash
sudo yum install unrar
# hoặc
sudo dnf install unrar
```

#### macOS

```bash
brew install unrar
```

#### Docker

Dockerfile đã được cập nhật để tự động cài đặt `unrar`:
```dockerfile
RUN apt-get update && apt-get install -y \
    ...
    unrar \
    ...
```

Nếu bạn đã build image trước khi cập nhật, cần rebuild:
```bash
cd backend/config
docker-compose build
```

### 3. Kiểm Tra Cài Đặt

#### Kiểm tra rarfile (Python)

```bash
python -c "import rarfile; print('rarfile OK')"
```

#### Kiểm tra unrar (Binary)

```bash
# Windows
where unrar
# hoặc
unrar

# Linux/macOS
which unrar
# hoặc
unrar
```

Nếu unrar không có trong PATH, bạn có thể chỉ định đường dẫn trong code:
```python
import rarfile
rarfile.UNRAR_TOOL = "C:/Program Files/WinRAR/unrar.exe"  # Windows
# hoặc
rarfile.UNRAR_TOOL = "/usr/bin/unrar"  # Linux
```

### 4. Test RAR Support

Sau khi cài đặt, test lại:

1. Tạo file RAR test
2. Upload qua giao diện Batch Scan
3. Kiểm tra xem có giải nén được không

### 5. Troubleshooting

#### Lỗi: "rarfile not found"

**Giải pháp:**
```bash
pip install rarfile==4.1
```

#### Lỗi: "Cannot find unrar"

**Giải pháp:**
- Cài đặt unrar binary (xem phần 2)
- Kiểm tra unrar có trong PATH không
- Nếu không, chỉ định đường dẫn trong code (xem phần 3)

#### Lỗi: "Invalid RAR file"

**Giải pháp:**
- Kiểm tra file RAR có hợp lệ không
- Thử với file RAR khác
- Kiểm tra version RAR (rarfile hỗ trợ RAR 1.0 - 5.0)

#### Docker: unrar not found

**Giải pháp:**
1. Đảm bảo Dockerfile có `unrar` trong apt-get install
2. Rebuild Docker image:
   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

### 6. Tùy Chọn: Disable RAR Support

Nếu không muốn hỗ trợ RAR, bạn có thể:

1. Xóa `rarfile==4.1` khỏi `requirements.txt`
2. Code sẽ tự động disable RAR support (RAR_SUPPORT = False)
3. Upload file RAR sẽ trả về lỗi: "RAR support not available"

---

## Tóm Tắt

✅ **Đã có trong code:**
- Backend hỗ trợ RAR (optional)
- Frontend cho phép chọn file RAR
- Translations đã có RAR

⚠️ **Cần cài đặt:**
1. `pip install rarfile==4.1` (Python package)
2. `unrar` binary (hệ thống)

📝 **Lưu ý:**
- RAR support là optional - nếu không cài đặt, hệ thống vẫn hoạt động bình thường
- Chỉ cần cài đặt nếu bạn muốn quét file RAR
- ZIP và TAR vẫn hoạt động mà không cần cài đặt thêm

