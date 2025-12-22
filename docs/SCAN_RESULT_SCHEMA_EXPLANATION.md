# Giải Thích Chi Tiết ScanResult Schema và Các Loại Response

## 1. ScanResult Schema - Cấu Trúc Dữ Liệu Chính

`ScanResult` là schema chính được sử dụng cho **TẤT CẢ** các API quét file (YARA, EMBER, hoặc quét đầy đủ).

### 1.1. Định Nghĩa Schema

```python
class ScanResult(BaseModel):
    """API response schema cho /api/scan - Kết quả scan file"""
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: List[str] = Field(default_factory=list)
    capabilities: List[Dict[str, Any]] = Field(default_factory=list)
    malware_detected: bool = False
    analysis_time: float = 0.0
    results: List[Dict[str, Any]] = Field(default_factory=list)
```

### 1.2. Giải Thích Chi Tiết Từng Trường

#### **`filename: str`**
- **Mô tả**: Tên file đã được quét
- **Ví dụ**: `"malware.exe"`, `"suspicious.dll"`
- **Nguồn**: Từ `file.filename` trong request upload

#### **`sha256: Optional[str]`**
- **Mô tả**: Giá trị băm SHA256 của file (64 ký tự hex)
- **Ví dụ**: `"80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68"`
- **Nguồn**: Được tính bởi `HashService.calculate_hash()` trong `analyzer_service.py`
- **Công dụng**: 
  - Định danh duy nhất file
  - Tạo link tham khảo đến bazaar.abuse.ch
  - So sánh với database malware (hiện tại đã tắt)

#### **`md5: Optional[str]`**
- **Mô tả**: Giá trị băm MD5 của file (32 ký tự hex)
- **Ví dụ**: `"7b106cafd8dd7b2c66de24feda2233ba"`
- **Nguồn**: Được tính bởi `HashService.calculate_hash()` (cả SHA256 và MD5 cùng lúc)
- **Công dụng**: Hỗ trợ tìm kiếm và so sánh

#### **`yara_matches: List[Dict[str, Any]]`**
- **Mô tả**: Danh sách các quy tắc YARA đã khớp với file, **CHI TIẾT**
- **Cấu trúc mỗi phần tử**:
  ```python
  {
      "rule_name": str,           # Tên quy tắc YARA (ví dụ: "DebuggerException")
      "tags": List[str],          # Tags của quy tắc (ví dụ: ["AntiDebug", "DebuggerException"])
      "description": Optional[str], # Mô tả quy tắc
      "author": Optional[str],     # Tác giả quy tắc
      "reference": Optional[str],  # Link tham khảo
      "matched_strings": [        # Các chuỗi/pattern đã khớp
          {
              "identifier": str,   # Tên identifier trong rule (ví dụ: "$s1")
              "offset": int,       # Vị trí trong file (hex offset)
              "data": str,         # Dữ liệu hex của chuỗi khớp
              "data_preview": str  # Preview dạng ASCII (nếu có thể decode)
          }
      ]
  }
  ```
- **Nguồn**: 
  - Từ `YaraService.scan_file()` → `detailed_matches`
  - Hoặc từ `StaticAnalyzer` nếu YARA scan không chạy
- **Lưu ý**: 
  - **LUÔN** có dữ liệu vì Static Analyzer luôn chạy (bất kể scan_modules)
  - Nếu quét YARA, sẽ có `yara_matches` từ YARA scan
  - Nếu không quét YARA, vẫn có `yara_matches` từ Static Analyzer (có thể rỗng)

#### **`pe_info: Optional[Dict[str, Any]]`**
- **Mô tả**: Thông tin chi tiết về cấu trúc PE file (chỉ có nếu file là PE)
- **Cấu trúc**:
  ```python
  {
      "machine": int,              # Loại máy (34404 = x64, 332 = x86)
      "timestamp": int,             # Timestamp biên dịch (Unix timestamp)
      "sections": [                # Các section trong PE
          {
              "name": str,         # Tên section (ví dụ: ".text", ".rdata")
              "entropy": float,    # Entropy của section (0-8)
              "raw_size": int,     # Kích thước trên disk
              "virtual_size": int, # Kích thước trong memory
              "virtual_address": int # Địa chỉ ảo
          }
      ],
      "imports": [                 # Các DLL và hàm được import
          {
              "dll": str,          # Tên DLL (ví dụ: "KERNEL32.dll")
              "function": str      # Tên hàm (ví dụ: "CreateFileW")
          }
      ],
      "exports": List[str],        # Các hàm được export (thường rỗng cho .exe)
      "suspicious_features": [    # Các đặc điểm đáng ngờ
          "High entropy section (possibly packed)",
          "Suspicious import: VirtualAlloc",
          ...
      ]
  }
  ```
- **Nguồn**: Từ `StaticAnalyzer._analyze_pe_file()` sử dụng thư viện `pefile`
- **Lưu ý**: 
  - Chỉ có nếu file là PE file hợp lệ
  - **LUÔN** được trích xuất bất kể scan_modules (Static Analyzer luôn chạy)

#### **`suspicious_strings: List[str]`**
- **Mô tả**: Danh sách các chuỗi ký tự đáng ngờ được phát hiện trong file
- **Ví dụ**:
  ```python
  [
      "http://malicious-site.com/payload",
      "192.168.1.100",
      "cmd.exe /c",
      "CreateRemoteThread",
      "HKEY_CURRENT_USER\\Software",
      "base64",
      "malware",
      ...
  ]
  ```
- **Nguồn**: Từ `StaticAnalyzer._extract_strings()` và `_is_suspicious_string()`

##### **Quy Trình Trích Xuất và So Sánh:**

**⚠️ QUAN TRỌNG: File KHÔNG CẦN chuyển đổi định dạng!**

Cả **YARA scan** và **suspicious strings extraction** đều làm việc trực tiếp với **binary data** (bytes) của file gốc, không cần chuyển đổi sang định dạng khác.

**BƯỚC 1: Đọc file dưới dạng binary (bytes)**
```python
# File được đọc dưới dạng binary (bytes) - KHÔNG chuyển đổi gì cả
with open(filepath, 'rb') as f:
    file_content = f.read()  # bytes object - dữ liệu gốc của file
```

**Lưu ý**:
- `'rb'` = read binary mode - đọc file dưới dạng bytes nguyên gốc
- Không decode, không parse, không chuyển đổi định dạng
- Giữ nguyên cấu trúc binary của file

**BƯỚC 2: Trích xuất ASCII strings từ bytes**
```python
# Duyệt từng byte trong file
for byte in content:
    if 32 <= byte <= 126:  # Printable ASCII (ký tự có thể in được)
        current_string.append(chr(byte))  # Chuyển byte → ký tự
    else:
        # Kết thúc chuỗi, kiểm tra độ dài
        if len(current_string) >= 4:  # Tối thiểu 4 ký tự
            s = ''.join(current_string)  # Ghép thành string
            if self._is_suspicious_string(s):  # So sánh
                strings.append(s)
```

**BƯỚC 3: Trích xuất Unicode strings (UTF-16 LE)**
```python
# Thử decode file thành UTF-16 Little Endian (Windows thường dùng)
unicode_content = content.decode('utf-16le', errors='ignore')
# Tìm các chuỗi printable ASCII (4+ ký tự)
for match in re.finditer(r'[\x20-\x7E]{4,}', unicode_content):
    s = match.group()
    if self._is_suspicious_string(s):  # So sánh
        strings.append(s)
```

**BƯỚC 4: So sánh với các tiêu chí đáng ngờ**

Hàm `_is_suspicious_string(s)` thực hiện **3 loại so sánh**:

1. **So sánh với Regex Patterns** (không phân biệt hoa/thường):
   ```python
   suspicious_patterns = [
       r'http[s]?://[^\s]+',              # URLs (http/https)
       r'ftp://[^\s]+',                    # FTP URLs
       r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
       r'[A-Z]:\\[^\\s]+',                 # Đường dẫn Windows (C:\...)
       r'\\\\[^\\s]+',                     # UNC paths (\\server\share)
       r'HKEY_[A-Z_]+',                    # Registry keys (HKEY_CURRENT_USER)
       r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
       r'[0-9a-fA-F]{32,}',                # Hex strings dài (hashes)
       r'cmd\.exe|powershell|wscript|cscript',  # Command execution
       r'CreateRemoteThread|VirtualAlloc|WriteProcessMemory',  # Dangerous APIs
       r'base64|Base64',                   # Encoding
       r'password|pwd|passwd|secret|key',  # Credentials
       r'\.dll|\.exe|\.sys|\.bat|\.ps1',   # Executable files
   ]
   
   # So sánh: re.search(pattern, s, re.IGNORECASE)
   for pattern in self.suspicious_patterns:
       if re.search(pattern, s, re.IGNORECASE):
           return True  # Khớp → đáng ngờ
   ```

2. **So sánh với Keywords** (không phân biệt hoa/thường):
   ```python
   suspicious_keywords = [
       'malware', 'trojan', 'virus', 'backdoor', 'keylogger',
       'ransomware', 'spyware', 'rootkit', 'botnet', 'exploit',
       'payload', 'shellcode', 'inject', 'hook', 'bypass',
       'disable', 'delete', 'kill', 'terminate', 'remove',
       'registry', 'startup', 'autostart', 'persistence',
       'crypto', 'encrypt', 'decrypt', 'ransom', 'bitcoin',
       'c2', 'command', 'control', 'server', 'connect',
       'download', 'upload', 'exfiltrate', 'steal', 'collect'
   ]
   
   # So sánh: keyword in s.lower()
   s_lower = s.lower()
   for keyword in self.suspicious_keywords:
       if keyword in s_lower:
           return True  # Khớp → đáng ngờ
   ```

3. **So sánh Entropy** (Shannon entropy cho strings dài):
   ```python
   # Chỉ kiểm tra strings >= 16 ký tự
   if len(s) >= 16 and self._has_high_entropy(s):
       return True  # Entropy cao → đáng ngờ (có thể là encoded/encrypted)
   
   # Tính Shannon entropy
   entropy = 0
   for char in set(s):
       p = s.count(char) / len(s)  # Tần suất xuất hiện
       if p > 0:
           entropy -= p * math.log2(p)
   
   # Ngưỡng: entropy > 4.0 (strings ngẫu nhiên có ~4.5-5.0)
   return entropy > 4.0
   ```

**BƯỚC 5: Sắp xếp và giới hạn**
```python
# Sắp xếp theo độ dài (dài nhất trước - ưu tiên strings dài hơn)
strings.sort(key=len, reverse=True)
return strings[:100]  # Giới hạn 100 strings đáng ngờ nhất
```

##### **Tóm Tắt Quy Trình:**

1. **File → Bytes**: Đọc file dưới dạng binary (`rb` mode)
2. **Bytes → ASCII Strings**: Duyệt từng byte, tìm chuỗi printable ASCII (4-200 ký tự)
3. **Bytes → Unicode Strings**: Decode UTF-16 LE, tìm chuỗi printable ASCII
4. **So sánh với 3 tiêu chí**:
   - Regex patterns (URLs, IPs, paths, commands, APIs, ...)
   - Keywords (malware, trojan, backdoor, ...)
   - High entropy (strings ngẫu nhiên/encoded)
5. **Lọc trùng**: Sử dụng `set()` để loại bỏ strings trùng lặp
6. **Sắp xếp**: Theo độ dài (dài nhất trước)
7. **Giới hạn**: 100 strings (sau đó cắt xuống 20 trong `analyzer_service.py`)

##### **So Sánh: YARA vs Suspicious Strings**

| Tiêu chí | YARA Scan | Suspicious Strings |
|----------|-----------|-------------------|
| **Đọc file** | YARA engine tự đọc từ disk (`rules.match(filepath)`) | Đọc binary: `open(filepath, 'rb')` |
| **Chuyển đổi** | ❌ **KHÔNG** - YARA làm việc trực tiếp với binary | ❌ **KHÔNG** - Chỉ đọc bytes |
| **Xử lý** | YARA engine quét patterns (strings, hex, regex) | Duyệt bytes → trích xuất strings → so sánh |
| **Kết quả** | Rules đã match | Danh sách strings đáng ngờ |

**Kết luận**: Cả hai đều làm việc với **binary data gốc**, không cần chuyển đổi file sang định dạng khác!

##### **Ví Dụ Cụ Thể:**

**Input**: File binary chứa bytes:
```
48 65 6C 6C 6F 20 68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73 2E 63 6F 6D
```

**Bước 1**: Chuyển bytes → ASCII string:
```python
"Hello http://malicious.com"
```

**Bước 2**: So sánh với regex pattern:
```python
r'http[s]?://[^\s]+'  # Khớp "http://malicious.com" → ĐÁNG NGỜ
```

**Bước 3**: Thêm vào `suspicious_strings`:
```python
["http://malicious.com"]
```

- **Giới hạn**: Tối đa 20 chuỗi (được cắt trong `analyzer_service.py` từ 100 → 20)

#### **`capabilities: List[Dict[str, Any]]`**
- **Mô tả**: Các khả năng của file (network, file system, registry, process manipulation)
- **Cấu trúc**:
  ```python
  [
      {
          "type": "network",       # Loại khả năng
          "description": "Có thể kết nối mạng",
          "indicators": ["WinHttpConnect", "InternetConnect"]
      },
      {
          "type": "file_system",
          "description": "Có thể thao tác file",
          "indicators": ["CreateFileW", "WriteFile"]
      },
      ...
  ]
  ```
- **Nguồn**: Từ `StaticAnalyzer._analyze_capabilities()` dựa trên imports
- **Các loại**:
  - `network`: Kết nối mạng (WinHttpConnect, InternetConnect, socket)
  - `file_system`: Thao tác file (CreateFileW, WriteFile, DeleteFileW)
  - `registry`: Thao tác registry (RegSetValueEx, RegCreateKeyEx)
  - `process_manipulation`: Thao tác process (CreateRemoteThread, VirtualAlloc)

#### **`malware_detected: bool`**
- **Mô tả**: Có phát hiện malware không (tổng hợp từ tất cả modules)
- **Logic xác định** (trong `analyzer_service.py`):
  ```python
  # Ưu tiên: YARA > Hash > EMBER
  if yara_matches:
      malware_detected = True
  elif hash_match:
      malware_detected = True
  elif ember_is_malware:
      malware_detected = True
  else:
      malware_detected = False
  ```
- **Nguồn**: Được tính trong `analyzer_service.analyze_and_save()`

#### **`analysis_time: float`**
- **Mô tả**: Thời gian phân tích (giây)
- **Ví dụ**: `3.26`, `0.45`
- **Nguồn**: Được tính từ lúc bắt đầu đến lúc kết thúc phân tích

#### **`results: List[Dict[str, Any]]`**
- **Mô tả**: **CHI TIẾT CÁC PHÁT HIỆN** từ từng module (Hash, YARA, EMBER)
- **Đây là phần QUAN TRỌNG NHẤT** - chứa kết quả từng module riêng biệt
- **Cấu trúc mỗi phần tử** phụ thuộc vào `type`:

---

## 2. Cấu Trúc `results[]` - Chi Tiết Từng Module

### 2.1. Hash Result (`type: "hash"`)

```python
{
    "type": "hash",
    "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
    "uri": "https://bazaar.abuse.ch/sample/...",
    "malwareType": "Trojan",
    "firstSeen": "2024-01-01",
    "infoUrl": "https://bazaar.abuse.ch/sample/...",
    "message": "[MALWARE] Hash match found in database"
}
```

- **Nguồn**: Từ `HashService.check_hash()` (hiện tại đã tắt, luôn trả về rỗng)
- **Lưu ý**: Module này hiện không hoạt động

### 2.2. YARA Result (`type: "yara"`)

```python
{
    "type": "yara",
    "file": "/path/to/file.exe",
    "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug, DebuggerException), anti_dbg - Checks if being debugged, ...",
    "rule_count": 17,
    "detailed_matches": [  # ← CHI TIẾT (giống yara_matches ở trên)
        {
            "rule_name": "DebuggerException__SetConsoleCtrl",
            "tags": ["AntiDebug", "DebuggerException"],
            "description": "Checks if being debugged",
            "author": "YARA Rule Author",
            "reference": "https://...",
            "matched_strings": [
                {
                    "identifier": "$s1",
                    "offset": 12345,
                    "data": "48656c6c6f",
                    "data_preview": "Hello"
                }
            ]
        }
    ],
    "infoUrl": "https://bazaar.abuse.ch/sample/{sha256}/"
}
```

- **Nguồn**: Từ `YaraService.scan_file()`
- **Lưu ý**: 
  - `matches` là chuỗi tổng hợp (dùng để hiển thị nhanh)
  - `detailed_matches` là danh sách chi tiết (dùng để lưu database và hiển thị đầy đủ)

### 2.3. EMBER Result - Phát Hiện Malware (`type: "model"`, `subtype: "ember"`)

```python
{
    "type": "model",
    "subtype": "ember",
    "message": "[MALWARE] EMBER detection (Score: 0.9234)",
    "score": 0.9234,              # Điểm số từ 0.0 đến 1.0
    "threshold": 0.8336,          # Ngưỡng (1% FPR)
    "infoUrl": None
}
```

- **Nguồn**: Từ `EmberModel.predict()` → `analyzer_service.analyze_single_file()`
- **Logic**:
  - Nếu `score > threshold` (0.8336) → `is_malware = True` → `type: "model"`, `message: "[MALWARE]"`
  - Nếu `score <= threshold` → `is_malware = False` → `type: "model"`, `message: "[CLEAN]"`

### 2.4. EMBER Result - File Sạch (`type: "model"`, `subtype: "ember"`)

```python
{
    "type": "model",
    "subtype": "ember",
    "message": "[CLEAN] EMBER analysis (Score: 0.1234, Threshold: 0.8336)",
    "score": 0.1234,
    "threshold": 0.8336,
    "infoUrl": None
}
```

- **Lưu ý**: EMBER **LUÔN** trả về kết quả (có score) dù file sạch hay không

### 2.5. EMBER Error (`type: "ember_error"`)

```python
{
    "type": "ember_error",
    "message": "[ERROR] EMBER prediction failed: ...",
    "score": 0.0,
    "error_detail": "Chi tiết lỗi",
    "error_type": "PEFormatError",
    "file_path": "/path/to/file.exe",
    "infoUrl": None
}
```

- **Nguyên nhân**:
  - File không phải PE
  - Lỗi trích xuất features
  - Lỗi model prediction
  - File quá nhỏ (< 64 bytes)

### 2.6. Clean Result (`type: "clean"`)

```python
{
    "type": "clean",
    "message": "[OK] Không phát hiện malware",
    "infoUrl": None
}
```

- **Nguồn**: Được thêm nếu không có kết quả nào từ Hash, YARA, hoặc EMBER

---

## 3. EMBER Response - Chi Tiết

### 3.1. EMBER Model Predict Method

```python
# backend/app/ml/ember_model.py
def predict(self, file_path: str) -> Dict[str, Any]:
    """Dự đoán file có phải malware không bằng EMBER model"""
    # Trả về:
    {
        "score": float,           # 0.0 - 1.0
        "is_malware": bool,       # score > threshold
        "model_name": str,        # Tên file model
        "threshold": float,       # 0.8336
        "error": Optional[str],   # Nếu có lỗi
        "error_detail": Optional[str],
        "error_type": Optional[str],
        "file_path": Optional[str]
    }
```

### 3.2. EMBER Score Calculation

1. **Kiểm tra PE file**: 
   - Phải có MZ header (bytes đầu tiên = `b'MZ'`)
   - Phải có PE signature (offset 0x3C)
   - File size >= 64 bytes

2. **Trích xuất features**:
   - Sử dụng `ember.features.PEFeatureExtractor`
   - Tổng cộng **2381 features**:
     - Histogram features (256)
     - Byte entropy (256)
     - Strings features (1024)
     - General features (10)
     - Header features (92)
     - Section features (512)
     - Imports features (128)
     - Exports features (64)
     - Data directories features (39)

3. **Dự đoán**:
   - Sử dụng LightGBM model (`ember_model_2018.txt`)
   - Score từ 0.0 (sạch) đến 1.0 (malware)
   - Threshold: **0.8336** (1% False Positive Rate)

### 3.3. Ví Dụ EMBER Response

#### **File Malware**:
```json
{
    "type": "model",
    "subtype": "ember",
    "message": "[MALWARE] EMBER detection (Score: 0.9234)",
    "score": 0.9234,
    "threshold": 0.8336,
    "infoUrl": null
}
```

#### **File Sạch**:
```json
{
    "type": "model",
    "subtype": "ember",
    "message": "[CLEAN] EMBER analysis (Score: 0.1234, Threshold: 0.8336)",
    "score": 0.1234,
    "threshold": 0.8336,
    "infoUrl": null
}
```

#### **File Không Phải PE**:
```json
{
    "type": "ember_error",
    "message": "[ERROR] EMBER prediction failed: File is not a valid PE file",
    "score": 0.0,
    "error_detail": "Invalid PE header. Expected 'MZ', got: ...",
    "error_type": "PEFormatError",
    "file_path": "/path/to/file.pdf",
    "infoUrl": null
}
```

---

## 4. Batch Scan Response - Chi Tiết

### 4.1. Batch Scan Upload Response

**Endpoint**: `POST /api/scan/folder-upload`

**Response Schema**:
```python
class BatchScanResponse(BaseModel):
    batch_id: str          # UUID của batch job
    total_files: int       # Tổng số file
    status: str            # 'pending', 'processing', 'completed', 'failed'
    processed: int         # Số file đã xử lý
    completed: int         # Số file hoàn thành
    failed: int            # Số file thất bại
```

**Ví dụ Response**:
```json
{
    "batch_id": "550e8400-e29b-41d4-a716-446655440000",
    "total_files": 10,
    "status": "pending",
    "processed": 0,
    "completed": 0,
    "failed": 0
}
```

**Xử lý**:
1. Nhận danh sách files từ FormData
2. Kiểm tra tổng kích thước (max 2GB)
3. Lưu files vào `uploads/temp_{batch_id}/`
4. Tạo batch job trong memory (`batch_jobs` dict)
5. Chạy `process_batch_scan()` trong background task
6. Trả về `batch_id` ngay lập tức

### 4.2. Batch Scan Status Response

**Endpoint**: `GET /api/scan/batch/{batch_id}/status`

**Response Schema**: Giống `BatchScanResponse` (không có `results` và `errors`)

**Ví dụ Response**:
```json
{
    "batch_id": "550e8400-e29b-41d4-a716-446655440000",
    "total_files": 10,
    "status": "processing",
    "processed": 7,
    "completed": 6,
    "failed": 1
}
```

**Status Values**:
- `pending`: Chưa bắt đầu xử lý
- `processing`: Đang xử lý
- `completed`: Hoàn thành tất cả
- `failed`: Thất bại toàn bộ

### 4.3. Batch Scan Results Response

**Endpoint**: `GET /api/scan/batch/{batch_id}`

**Response Schema**:
```python
class BatchScanResult(BaseModel):
    batch_id: str
    status: str
    total_files: int
    processed: int
    completed: int
    failed: int
    results: List[dict]    # Kết quả chi tiết từng file
    errors: List[dict]     # Lỗi từng file
```

**Cấu Trúc `results[]`**:
```python
[
    {
        "filename": "file1.exe",
        "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
        "malware_detected": True,
        "analysis_id": 123  # ID trong database (nếu lưu thành công)
    },
    {
        "filename": "file2.dll",
        "sha256": "...",
        "malware_detected": False,
        "analysis_id": 124
    }
]
```

**Cấu Trúc `errors[]`**:
```python
[
    {
        "filename": "file3.exe",
        "error": "File is not a valid PE file. EMBER only analyzes PE files."
    },
    {
        "filename": "file4.pdf",
        "error": "File size exceeds maximum allowed size (2GB)"
    }
]
```

**Ví dụ Response Đầy Đủ**:
```json
{
    "batch_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "total_files": 10,
    "processed": 10,
    "completed": 9,
    "failed": 1,
    "results": [
        {
            "filename": "malware1.exe",
            "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
            "malware_detected": true,
            "analysis_id": 123
        },
        {
            "filename": "clean.exe",
            "sha256": "7b106cafd8dd7b2c66de24feda2233ba...",
            "malware_detected": false,
            "analysis_id": 124
        }
    ],
    "errors": [
        {
            "filename": "not_pe.pdf",
            "error": "File is not a valid PE file. EMBER only analyzes PE files."
        }
    ]
}
```

### 4.4. Batch Scan Processing Flow

1. **Upload Files**:
   - Frontend gửi FormData với nhiều files
   - Backend lưu vào `uploads/temp_{batch_id}/`
   - Tạo batch job trong `batch_jobs` dict

2. **Background Processing**:
   - Chạy `process_batch_scan()` trong background task
   - Với mỗi file:
     - Gọi `analyzer_service.analyze_and_save()`
     - Cập nhật `processed`, `completed`, `failed`
     - Lưu kết quả vào `job["results"]` hoặc `job["errors"]`

3. **Polling Status**:
   - Frontend gọi `GET /api/scan/batch/{batch_id}/status` định kỳ
   - Kiểm tra `status` và `processed` vs `total_files`

4. **Get Results**:
   - Khi `status == "completed"`, gọi `GET /api/scan/batch/{batch_id}`
   - Nhận danh sách `results` và `errors` đầy đủ

---

## 5. So Sánh Các Loại Response

### 5.1. YARA Scan (`POST /api/scan/yara`)

```json
{
    "filename": "file.exe",
    "sha256": "...",
    "md5": "...",
    "yara_matches": [...],        // ← Từ YARA scan
    "pe_info": {...},              // ← Từ Static Analyzer (LUÔN có)
    "suspicious_strings": [...],   // ← Từ Static Analyzer (LUÔN có)
    "capabilities": [...],         // ← Từ Static Analyzer (LUÔN có)
    "malware_detected": true,      // ← Dựa trên yara_matches
    "analysis_time": 2.5,
    "results": [
        {
            "type": "yara",
            "matches": "...",
            "rule_count": 17,
            "detailed_matches": [...]
        }
    ]
}
```

**Đặc điểm**:
- `results[]` chỉ có YARA result
- `yara_matches` có dữ liệu từ YARA scan
- Static Analyzer **LUÔN** chạy → có `pe_info`, `suspicious_strings`, `capabilities`

### 5.2. EMBER Scan (`POST /api/scan/ember`)

```json
{
    "filename": "file.exe",
    "sha256": "...",
    "md5": "...",
    "yara_matches": [],            // ← Từ Static Analyzer (có thể rỗng)
    "pe_info": {...},              // ← Từ Static Analyzer (LUÔN có nếu là PE)
    "suspicious_strings": [...],   // ← Từ Static Analyzer (LUÔN có)
    "capabilities": [...],         // ← Từ Static Analyzer (LUÔN có)
    "malware_detected": true,      // ← Dựa trên EMBER score
    "analysis_time": 3.2,
    "results": [
        {
            "type": "model",
            "subtype": "ember",
            "message": "[MALWARE] EMBER detection (Score: 0.9234)",
            "score": 0.9234,
            "threshold": 0.8336
        }
    ]
}
```

**Đặc điểm**:
- `results[]` chỉ có EMBER result
- `yara_matches` từ Static Analyzer (không từ YARA scan)
- Static Analyzer **LUÔN** chạy → có `pe_info`, `suspicious_strings`, `capabilities`
- Phải là PE file (kiểm tra MZ header)

### 5.3. Full Scan (`POST /api/scan`)

```json
{
    "filename": "file.exe",
    "sha256": "...",
    "md5": "...",
    "yara_matches": [...],         // ← Từ YARA scan
    "pe_info": {...},              // ← Từ Static Analyzer (LUÔN có)
    "suspicious_strings": [...],   // ← Từ Static Analyzer (LUÔN có)
    "capabilities": [...],         // ← Từ Static Analyzer (LUÔN có)
    "malware_detected": true,      // ← Tổng hợp từ YARA, Hash, EMBER
    "analysis_time": 5.8,
    "results": [
        {
            "type": "hash",
            ...
        },
        {
            "type": "yara",
            "matches": "...",
            "rule_count": 17,
            "detailed_matches": [...]
        },
        {
            "type": "model",
            "subtype": "ember",
            "score": 0.9234,
            "threshold": 0.8336
        }
    ]
}
```

**Đặc điểm**:
- `results[]` có tất cả: Hash, YARA, EMBER
- `yara_matches` từ YARA scan (chi tiết)
- Static Analyzer **LUÔN** chạy → có `pe_info`, `suspicious_strings`, `capabilities`

---

## 6. Tóm Tắt

### 6.1. ScanResult Schema

| Trường | Mô Tả | Nguồn |
|--------|-------|-------|
| `filename` | Tên file | Request upload |
| `sha256` | Hash SHA256 | HashService |
| `md5` | Hash MD5 | HashService |
| `yara_matches` | YARA matches chi tiết | YaraService hoặc StaticAnalyzer |
| `pe_info` | Thông tin PE file | StaticAnalyzer (LUÔN chạy) |
| `suspicious_strings` | Chuỗi đáng ngờ | StaticAnalyzer (LUÔN chạy) |
| `capabilities` | Khả năng file | StaticAnalyzer (LUÔN chạy) |
| `malware_detected` | Có phát hiện malware | Tổng hợp từ YARA/Hash/EMBER |
| `analysis_time` | Thời gian phân tích | Tính toán |
| `results[]` | Chi tiết từng module | HashService, YaraService, EmberModel |

### 6.2. EMBER Response

- **Thành công**: `type: "model"`, `subtype: "ember"`, có `score` và `threshold`
- **Lỗi**: `type: "ember_error"`, có `error_detail` và `error_type`
- **Luôn trả về**: Dù file sạch hay không, EMBER luôn trả về score

### 6.3. Batch Scan Response

- **Upload**: Trả về `batch_id` ngay lập tức
- **Status**: Polling để kiểm tra tiến độ
- **Results**: Khi hoàn thành, trả về danh sách `results[]` và `errors[]`

---

## 7. Code References

- **ScanResult Schema**: `backend/app/schemas/scan.py:28-39`
- **YARA Service**: `backend/app/services/yara_service.py:30-129`
- **EMBER Model**: `backend/app/ml/ember_model.py:178-297`
- **Analyzer Service**: `backend/app/services/analyzer_service.py:36-124`
- **Batch Scan API**: `backend/app/api/v1/routes/batch_scan.py:402-435`
- **Scan API**: `backend/app/api/v1/routes/scan.py:23-177`

