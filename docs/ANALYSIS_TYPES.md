# 📊 Các Loại Phân Tích Malware

## 🔍 Phân Tích Theo YARA Rules

### 1. **YARA Rules là gì?**

YARA Rules là **pattern matching** - quét file để tìm các pattern/signature đặc trưng của malware.

**Cách hoạt động:**

- YARA rules chứa các pattern (chuỗi, regex, conditions)
- Quét file để tìm pattern khớp
- Nếu khớp → phát hiện malware

**Ví dụ YARA rule:**

```yara
rule Trojan_Win32_Example {
    strings:
        $a = "malicious_string"
        $b = /evil_[a-z]+/
    condition:
        $a and $b
}
```

### 2. **Loại Phân Tích: Static Analysis (Phân Tích Tĩnh)**

**Static Analysis** = Phân tích file **KHÔNG cần chạy** file đó

**Đặc điểm:**

- ✅ An toàn - không chạy malware
- ✅ Nhanh - chỉ đọc file
- ✅ Phân tích: strings, patterns, PE headers, metadata
- ❌ Không phát hiện behavior (hành vi khi chạy)

**So sánh với Dynamic Analysis:**

- **Static**: Phân tích code/file không chạy
- **Dynamic**: Chạy file trong sandbox, quan sát behavior

### 3. **Các Phương Pháp Phân Tích Hiện Tại**

#### a) **YARA Rules Scanning**

```python
# Quét file với YARA rules
yara_results = yara_service.scan_file(filepath)
# Trả về: rule name, tags, description
```

**Dữ liệu:**

- Rule name (tên rule khớp)
- Tags (phân loại: trojan, ransomware, etc.)
- Description (mô tả malware)
- **KHÔNG cần database** - chỉ cần rules file

#### b) **Hash-based Detection**

```python
# Tính SHA256 → tra cứu database
sha256 = sha256_hash(filepath)
malwares = await get_malware_by_list_sha256([sha256])
```

**Dữ liệu cần:**

- Database/JSON chứa hash đã biết
- Hiện tại: `src/Database/Malware.json`
- **CẦN database** để tra cứu

#### c) **Static Analyzer (PE Analysis)**

```python
# Phân tích PE file (Windows executable)
analysis = static_analyzer.analyze_file(filepath)
# Trả về: PE info, strings, capabilities
```

**Dữ liệu:**

- PE headers, sections, imports
- Suspicious strings
- Capabilities (packer, obfuscation, etc.)
- **KHÔNG cần database** - phân tích trực tiếp

## 💾 Database - Có Cần Không?

### ✅ **Hiện Tại Đang Dùng:**

1. **Hash Database** (`Malware.json`)
   - **Mục đích**: Tra cứu hash đã biết
   - **Dữ liệu**: SHA256, malwareType, firstSeen
   - **Cần thiết**: ✅ CÓ - để phát hiện malware đã biết

### ❓ **Có Nên Lưu Kết Quả Phân Tích?**

#### **Option 1: KHÔNG lưu (Hiện tại)**

- ✅ Đơn giản, nhanh
- ✅ Không tốn storage
- ❌ Không có lịch sử
- ❌ Không thể so sánh theo thời gian

#### **Option 2: Lưu vào Database (Nên làm)**

**Lợi ích:**

- ✅ Lịch sử phân tích
- ✅ Thống kê, báo cáo
- ✅ Phân tích xu hướng
- ✅ Tránh phân tích lại file đã quét

**Dữ liệu nên lưu:**

```sql
CREATE TABLE analyses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255),
    sha256 VARCHAR(64),
    md5 VARCHAR(32),
    file_size BIGINT,
    upload_time DATETIME,
    analysis_time FLOAT,
    malware_detected BOOLEAN,
    yara_matches JSON,
    pe_info JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE yara_matches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    analysis_id INT,
    rule_name VARCHAR(255),
    tags TEXT,
    description TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
```

## 🎯 Khuyến Nghị

### **Cho YARA Rules:**

- ❌ **KHÔNG cần database** để lưu rules
- ✅ Rules được load từ file `.yar`
- ✅ Chỉ cần file system

### **Cho Kết Quả Phân Tích:**

- ✅ **NÊN có database** để lưu:
  - Lịch sử phân tích
  - Thống kê malware
  - Báo cáo theo thời gian
  - Tránh phân tích trùng lặp

### **Cho Hash Lookup:**

- ✅ **CẦN database** (hiện có JSON)
- ✅ Nên chuyển sang SQL database
- ✅ Dễ query, index, scale

## 📝 Tóm Tắt

| Loại                  | Cần Database? | Lý Do                    |
| --------------------- | ------------- | ------------------------ |
| **YARA Rules**        | ❌ KHÔNG      | Rules từ file `.yar`     |
| **Hash Lookup**       | ✅ CÓ         | Tra cứu hash đã biết     |
| **Kết Quả Phân Tích** | ✅ NÊN CÓ     | Lưu lịch sử, thống kê    |
| **Static Analysis**   | ❌ KHÔNG      | Phân tích trực tiếp file |

## 🚀 Cải Thiện Đề Xuất

1. **Thêm Database cho Analysis History**

   - SQLite (đơn giản) hoặc MySQL/PostgreSQL
   - Lưu mỗi lần phân tích
   - API để xem lịch sử

2. **Cải Thiện Hash Database**

   - Chuyển từ JSON → SQL database
   - Index SHA256 để query nhanh
   - Tự động cập nhật từ threat intelligence feeds

3. **Thêm Analytics Dashboard**
   - Thống kê malware theo thời gian
   - Top malware types
   - Phân tích xu hướng
