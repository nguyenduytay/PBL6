# 📦 Hướng Dẫn Requirements.txt - Các Thư Viện Cần Thiết

## ✅ Thư Viện BẮT BUỘC (Core Dependencies)

### **1. FastAPI & Server**
```txt
fastapi==0.115.9          # ⭐ Web framework chính
uvicorn==0.34.2           # ⭐ ASGI server để chạy FastAPI
python-multipart==0.0.6   # ⭐ Cần cho file upload (FormData)
starlette==0.45.3         # FastAPI dependency
pydantic==2.11.4          # ⭐ Data validation (FastAPI dependency)
pydantic_core==2.33.2     # Pydantic core
```

**Giải thích:**
- `fastapi` - Framework chính
- `uvicorn` - Server để chạy FastAPI
- `python-multipart` - **BẮT BUỘC** để upload file qua API
- `pydantic` - Validate request/response data

---

### **2. MySQL Connection** ⭐ **CẦN THIẾT**

```txt
aiomysql==0.2.0           # ⭐ Async MySQL driver (BẮT BUỘC)
PyMySQL==1.1.2            # Dependency của aiomysql
```

**Giải thích:**
- `aiomysql` - **CẦN THIẾT** để kết nối MySQL (async)
- `PyMySQL` - Dependency của aiomysql (tự động cài)

**Code sử dụng:**
```python
# backend/app/database/connection.py
import aiomysql
pool = await aiomysql.create_pool(...)
```

**Lưu ý:**
- ✅ **CẦN** `aiomysql` để kết nối database
- ✅ Database là **tùy chọn** (nếu không có, app vẫn chạy được)
- ✅ Nếu không dùng database, có thể bỏ qua nhưng sẽ không lưu lịch sử

---

### **3. YARA & Malware Analysis**
```txt
yara-python==4.5.4        # ⭐ YARA engine để quét malware
pefile==2023.2.7          # ⭐ Phân tích PE files (Windows executables)
lief==0.17.0              # Binary analysis library
```

**Giải thích:**
- `yara-python` - **BẮT BUỘC** để quét malware với YARA rules
- `pefile` - Phân tích PE files (Windows executables)
- `lief` - Binary analysis

---

### **4. Environment & Config**
```txt
python-dotenv==1.1.0      # ⭐ Đọc file .env
```

**Giải thích:**
- `python-dotenv` - Đọc biến môi trường từ file `.env`

---

### **5. Utilities**
```txt
python-dateutil==2.8.2   # Xử lý dates
pytz==2025.2             # Timezone
```

---

## ⚠️ Thư Viện CÓ THỂ THỪA (Có thể xóa nếu không dùng)

### **1. Flask & Jinja2** (Không cần vì dùng React)
```txt
Flask==3.1.1              # ❌ Không cần (dùng FastAPI)
Jinja2==3.1.2             # ❌ Không cần (không render HTML)
Werkzeug==3.1.3           # ❌ Dependency của Flask
```

**Lý do xóa:**
- Đã dùng React frontend riêng
- Không cần render HTML templates
- FastAPI đã đủ

---

### **2. AI/ML Libraries** (Có thể không cần)
```txt
torch==2.7.0              # ❓ Machine learning (có thể không cần)
transformers==4.52.2      # ❓ NLP models
llama-index-*             # ❓ LLM integration (nhiều packages)
langchain-*               # ❓ LangChain (nhiều packages)
openai==1.81.0            # ❓ OpenAI API
google-generativeai       # ❓ Google AI
```

**Lý do:**
- Dự án hiện tại chỉ làm **static analysis**
- Chưa có dynamic analysis hoặc AI features
- Có thể xóa để giảm kích thước

---

### **3. Database Khác** (Không dùng)
```txt
aiosqlite==0.21.0         # ❌ SQLite (không dùng)
psycopg2==2.9.9           # ❌ PostgreSQL (không dùng)
pymongo==4.1.1            # ❌ MongoDB (không dùng)
motor==3.0.0              # ❌ MongoDB async (không dùng)
```

**Lý do:**
- Chỉ dùng MySQL (`aiomysql`)
- Các database khác không cần

---

### **4. Web Scraping & Other**
```txt
beautifulsoup4==4.13.4   # ❓ Web scraping (có thể không cần)
requests==2.31.0          # ❓ HTTP client (FastAPI có sẵn)
selenium                   # ❓ Browser automation (nếu có)
```

---

## 📋 Requirements Tối Thiểu (Minimal)

Nếu muốn giảm dependencies, chỉ cần các thư viện sau:

```txt
# Core FastAPI
fastapi==0.115.9
uvicorn==0.34.2
python-multipart==0.0.6
pydantic==2.11.4
pydantic_core==2.33.2
starlette==0.45.3

# MySQL
aiomysql==0.2.0
PyMySQL==1.1.2

# YARA & Analysis
yara-python==4.5.4
pefile==2023.2.7

# Config
python-dotenv==1.1.0

# Utilities
python-dateutil==2.8.2
```

**Tổng: ~15 packages** (thay vì 229 packages hiện tại)

---

## 🎯 Khuyến Nghị

### **Option 1: Giữ Nguyên (Khuyến nghị)**
- ✅ Giữ tất cả dependencies
- ✅ Dễ mở rộng sau này
- ✅ Không lo thiếu thư viện

### **Option 2: Tối Ưu (Nếu muốn giảm)**
- ✅ Xóa Flask, Jinja2 (không dùng)
- ✅ Xóa AI/ML libraries (chưa dùng)
- ✅ Xóa database khác (chỉ dùng MySQL)
- ⚠️ Có thể thiếu thư viện khi mở rộng

---

## 📊 Tóm Tắt

### **Thư Viện BẮT BUỘC:**
1. ✅ **FastAPI** - Web framework
2. ✅ **uvicorn** - Server
3. ✅ **python-multipart** - File upload
4. ✅ **aiomysql** - **MySQL connection** ⭐
5. ✅ **yara-python** - YARA engine
6. ✅ **pefile** - PE analysis
7. ✅ **python-dotenv** - Environment variables

### **MySQL Connection:**
- ✅ **CẦN** `aiomysql==0.2.0` để kết nối MySQL
- ✅ `PyMySQL` tự động cài cùng aiomysql
- ✅ Database là **tùy chọn** (app vẫn chạy được nếu không có)

### **Thư Viện Có Thể Xóa:**
- ❌ Flask, Jinja2, Werkzeug (không dùng)
- ❌ AI/ML libraries (chưa dùng)
- ❌ Database khác (chỉ dùng MySQL)

---

## 🔧 Cách Cài Đặt

### **Cài Tất Cả:**
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### **Cài Chỉ Core (Nếu tối ưu):**
```powershell
pip install fastapi uvicorn python-multipart aiomysql yara-python pefile python-dotenv
```

---

## ✅ Kết Luận

**MySQL Connection:**
- ✅ **CẦN** `aiomysql` để kết nối MySQL
- ✅ Đã có trong `requirements.txt` (line 3)
- ✅ Tự động cài khi chạy `pip install -r requirements.txt`

**Các Thư Viện Khác:**
- ✅ FastAPI, uvicorn - Bắt buộc
- ✅ python-multipart - Bắt buộc cho file upload
- ✅ yara-python, pefile - Bắt buộc cho malware analysis
- ⚠️ Flask, Jinja2 - Có thể xóa (không dùng)
- ⚠️ AI/ML libraries - Có thể xóa (chưa dùng)

