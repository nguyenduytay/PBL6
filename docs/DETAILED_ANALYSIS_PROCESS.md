# Quy Trình Phân Tích File Malware - Chi Tiết Từng Bước

## Mục Lục

1. [Tổng Quan Quy Trình](#tổng-quan-quy-trình)
2. [Bước 1: Nhận và Lưu File](#bước-1-nhận-và-lưu-file)
3. [Bước 2: Hash Service - Tính Hash](#bước-2-hash-service---tính-hash)
4. [Bước 3: YARA Service - Quét Patterns](#bước-3-yara-service---quét-patterns)
5. [Bước 4: Static Analyzer - Phân Tích Tĩnh](#bước-4-static-analyzer---phân-tích-tĩnh)
6. [Bước 5: EMBER Model - Machine Learning](#bước-5-ember-model---machine-learning)
7. [Bước 6: Tổng Hợp Kết Quả](#bước-6-tổng-hợp-kết-quả)
8. [Bước 7: Lưu Database](#bước-7-lưu-database)
9. [Bước 8: Trả Response](#bước-8-trả-response)
10. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

---

## Tổng Quan Quy Trình

Khi người dùng upload file, hệ thống thực hiện phân tích qua **8 bước chính**:

```
Upload File
    ↓
[1] Lưu file vào uploads/
    ↓
[2] Hash Service: Tính SHA256, MD5
    ↓
[3] YARA Service: Quét 12,159 rules
    ↓
[4] Static Analyzer: Parse PE, extract strings
    ↓
[5] EMBER Model: Extract 2381 features → Predict
    ↓
[6] Tổng hợp kết quả → Xác định malware_detected
    ↓
[7] Lưu vào MySQL database
    ↓
[8] Trả JSON response → Frontend hiển thị
```

---

## Bước 1: Nhận và Lưu File

### Frontend (React)

**File**: `frontend/src/pages/Upload/Upload.tsx`

```typescript
// Người dùng chọn file
const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0]
  setFile(file)
}

// Gửi request
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault()
  const formData = new FormData()
  formData.append('file', file)
  
  // Gửi đến backend
  await scan(file, scanType)  // 'yara' | 'ember' | 'full'
}
```

**Hook**: `frontend/src/hooks/useScan.ts`

```typescript
const scan = async (file: File, scanType: ScanType = 'full') => {
  let endpoint = '/scan'
  if (scanType === 'yara') endpoint = '/scan/yara'
  if (scanType === 'ember') endpoint = '/scan/ember'
  
  const response = await axiosClient.post(endpoint, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}
```

### Backend API

**File**: `backend/app/api/v1/routes/scan.py`

```python
@router.post("", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    # 1.1. Kiểm tra tên file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    # 1.2. Lưu file vào thư mục uploads/
    filepath = settings.UPLOAD_FOLDER / file.filename
    # Ví dụ: uploads/malware.exe
    
    with open(filepath, "wb") as f:
        content = await file.read()  # Đọc toàn bộ nội dung file
        f.write(content)  # Ghi vào disk
    
    # 1.3. Gọi AnalyzerService để phân tích
    analysis_data = await analyzer_service.analyze_and_save(
        str(filepath),
        file.filename
    )
    
    # 1.4. Xóa file tạm sau khi xử lý (trong finally block)
    if filepath.exists():
        os.remove(filepath)
```

**Kết quả Bước 1**:
- File được lưu tại: `backend/uploads/malware.exe`
- File size: Ví dụ 1.61 MB
- Sẵn sàng để phân tích

---

## Bước 2: Hash Service - Tính Hash

### Code Implementation

**File**: `backend/app/services/hash_service.py`

```python
def sha256_hash(filepath: str) -> Optional[str]:
    """Tính SHA256 hash của file"""
    with open(filepath, 'rb') as f:
        file_content = f.read()  # Đọc toàn bộ file vào memory
        return hashlib.sha256(file_content).hexdigest()
```

### Quy Trình Chi Tiết

1. **Đọc file**:
   ```python
   with open(filepath, 'rb') as f:
       content = f.read()  # Đọc binary
   ```

2. **Tính SHA256**:
   ```python
   sha256_hash = hashlib.sha256()
   sha256_hash.update(content)
   sha256 = sha256_hash.hexdigest()
   # Ví dụ: "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68"
   ```

3. **Tính MD5** (trong Static Analyzer):
   ```python
   md5_hash = hashlib.md5()
   md5_hash.update(content)
   md5 = md5_hash.hexdigest()
   # Ví dụ: "7b106cafd8dd7b2c66de24feda2233ba"
   ```

### Kết Quả

```python
{
    "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
    "md5": "7b106cafd8dd7b2c66de24feda2233ba"
}
```

**Lưu ý**: Hash được sử dụng để:
- Tạo infoUrl: `https://bazaar.abuse.ch/sample/{sha256}/`
- Lưu vào database để tra cứu sau
- So sánh với malware database (hiện tại đã disable)

---

## Bước 3: YARA Service - Quét Patterns

### Code Implementation

**File**: `backend/app/services/yara_service.py`

### 3.1. Khởi Tạo YARA Rules

```python
class YaraService:
    def __init__(self):
        # Load YARA rules từ yara_rules/rules/index.yar
        self.rules = settings.get_yara_rules()
        # 12,159 rules đã được compile sẵn
```

**Quy trình load rules**:
1. Đọc file `yara_rules/rules/index.yar`
2. Compile tất cả rules thành YARA engine
3. Lưu vào memory để sử dụng

### 3.2. Quét File

```python
def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
    # 3.2.1. Gọi YARA engine để match
    matches = self.rules.match(filepath)
    # YARA sẽ:
    # - Đọc file từng chunk
    # - So khớp với tất cả 12,159 rules
    # - Trả về list các rules đã match
```

**Ví dụ kết quả từ YARA**:
```python
matches = [
    Match(rule='DebuggerException__SetConsoleCtrl', tags=['AntiDebug']),
    Match(rule='anti_dbg', tags=['AntiDebug']),
    Match(rule='IsPE64', tags=['PECheck']),
    # ... 15 matches tổng cộng
]
```

### 3.3. Extract Match Details

```python
detailed_matches = []
for match in matches:
    match_obj = {
        "rule_name": str(match.rule),  # "DebuggerException__SetConsoleCtrl"
        "tags": list(match.tags),      # ["AntiDebug", "DebuggerException"]
        "description": match.meta.get('description'),
        "author": match.meta.get('author'),
        "reference": match.meta.get('reference'),
        "matched_strings": []
    }
    
    # 3.3.1. Extract matched strings
    for s in match.strings:
        # s là yara.StringMatch object
        string_info = {
            "identifier": getattr(s, 'identifier', None),  # "$s1"
            "offset": getattr(s, 'offset', None),           # 1024 (byte offset)
            "data": getattr(s, 'data', None).hex(),         # "4d5a9000" (hex)
            "data_preview": getattr(s, 'data', None).decode('ascii', errors='ignore')  # "MZ..."
        }
        match_obj["matched_strings"].append(string_info)
    
    detailed_matches.append(match_obj)
```

**Ví dụ matched_strings**:
```json
{
  "identifier": "$s1",
  "offset": 1024,
  "data": "4d5a90000300000004000000ffff0000",
  "data_preview": "MZ..."
}
```

### 3.4. Tạo Result Object

```python
results.append({
    "type": "yara",
    "file": filepath,
    "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug), anti_dbg, ...",
    "rule_count": 15,
    "detailed_matches": [
        {
            "rule_name": "DebuggerException__SetConsoleCtrl",
            "tags": ["AntiDebug", "DebuggerException"],
            "description": "Detects debugger evasion",
            "matched_strings": [...]
        },
        // ... 14 matches khác
    ],
    "infoUrl": None  # Sẽ được điền sau bằng SHA256
})
```

### Kết Quả Bước 3

```python
[
    {
        "type": "yara",
        "rule_count": 15,
        "detailed_matches": [
            {
                "rule_name": "DebuggerException__SetConsoleCtrl",
                "tags": ["AntiDebug"],
                "matched_strings": [
                    {"identifier": "$s1", "offset": 1024, "data": "4d5a...", "data_preview": "MZ..."}
                ]
            }
        ]
    }
]
```

---

## Bước 4: Static Analyzer - Phân Tích Tĩnh

### Code Implementation

**File**: `backend/app/services/static_analyzer_impl.py`

### 4.1. Extract Strings

```python
def _extract_strings(self, content: bytes) -> List[str]:
    """Trích xuất strings đáng ngờ từ binary"""
    strings = []
    
    # 4.1.1. Trích xuất ASCII strings (>= 4 ký tự)
    current_string = []
    for byte in content:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= 4:
                s = ''.join(current_string)
                # 4.1.2. Kiểm tra có đáng ngờ không
                if self._is_suspicious_string(s):
                    strings.append(s)
            current_string = []
    
    # 4.1.3. Trích xuất Unicode strings (UTF-16 LE)
    unicode_content = content.decode('utf-16le', errors='ignore')
    for match in re.finditer(r'[\x20-\x7E]{4,}', unicode_content):
        s = match.group()
        if self._is_suspicious_string(s):
            strings.append(s)
    
    return strings[:100]  # Giới hạn 100 strings
```

### 4.2. Kiểm Tra String Đáng Ngờ

```python
def _is_suspicious_string(self, s: str) -> bool:
    """Kiểm tra string có đáng ngờ không"""
    s_lower = s.lower()
    
    # 4.2.1. Kiểm tra patterns (regex)
    suspicious_patterns = [
        r'http[s]?://[^\s]+',           # URLs
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
        r'HKEY_[A-Z_]+',                # Registry keys
        r'cmd\.exe|powershell',          # Command execution
        r'CreateRemoteThread|VirtualAlloc',  # API calls
        r'base64|Base64',                # Encoding
        r'password|pwd|secret',          # Credentials
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, s, re.IGNORECASE):
            return True
    
    # 4.2.2. Kiểm tra keywords
    suspicious_keywords = [
        'malware', 'trojan', 'backdoor', 'keylogger',
        'ransomware', 'exploit', 'payload', 'shellcode',
        'inject', 'hook', 'bypass', 'crypto', 'encrypt'
    ]
    
    for keyword in suspicious_keywords:
        if keyword in s_lower:
            return True
    
    # 4.2.3. Kiểm tra entropy cao (strings ngẫu nhiên)
    if len(s) >= 16 and self._has_high_entropy(s):
        return True
    
    return False
```

**Ví dụ strings đáng ngờ**:
```python
[
    "http://192.168.1.100:8080/command",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "CreateRemoteThread",
    "base64",
    "Py_DecodeLocale",
    "registry_startup_demo"
]
```

### 4.3. Phân Tích PE File

```python
def _analyze_pe_file(self, filepath: str, content: bytes) -> Optional[Dict[str, Any]]:
    """Phân tích cấu trúc file PE"""
    import pefile
    pe = pefile.PE(filepath, fast_load=True)
    
    pe_info = {
        "machine": pe.FILE_HEADER.Machine,        # 34404 (x64)
        "timestamp": pe.FILE_HEADER.TimeDateStamp,  # Unix timestamp
        "sections": [],
        "imports": [],
        "exports": [],
        "suspicious_features": []
    }
    
    # 4.3.1. Phân tích sections
    for section in pe.sections:
        section_data = {
            "name": section.Name.decode('utf-8').rstrip('\x00'),  # ".text"
            "virtual_address": section.VirtualAddress,            # 4096
            "virtual_size": section.Misc_VirtualSize,            # 184752
            "raw_size": section.SizeOfRawData,                   # 184832
            "entropy": self._calculate_entropy(section.get_data())  # 6.48
        }
        pe_info["sections"].append(section_data)
        
        # 4.3.2. Kiểm tra entropy cao (có thể bị pack)
        if section_data["entropy"] > 7.0:
            pe_info["suspicious_features"].append(
                "High entropy section (possibly packed)"
            )
    
    # 4.3.3. Phân tích imports (các hàm được import)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')  # "KERNEL32.dll"
        for imp in entry.imports:
            if imp.name:
                pe_info["imports"].append({
                    "dll": dll_name,
                    "function": imp.name.decode('utf-8')  # "CreateFileW"
                })
    
    # 4.3.4. Phân tích exports (các hàm được export)
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                pe_info["exports"].append(
                    exp.name.decode('utf-8')
                )
    
    return pe_info
```

**Ví dụ PE Info**:
```json
{
  "machine": 34404,
  "timestamp": 1766198511,
  "sections": [
    {
      "name": ".text",
      "entropy": 6.48,
      "raw_size": 184832,
      "virtual_size": 184752
    },
    {
      "name": ".rsrc",
      "entropy": 7.35,
      "raw_size": 61440,
      "virtual_size": 61324
    }
  ],
  "imports": [
    {"dll": "KERNEL32.dll", "function": "CreateFileW"},
    {"dll": "KERNEL32.dll", "function": "WriteFile"},
    {"dll": "USER32.dll", "function": "ShowWindow"}
  ],
  "suspicious_features": [
    "High entropy section (possibly packed)"
  ]
}
```

### 4.4. Extract Capabilities

```python
def _extract_capabilities(self, pe_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Trích xuất khả năng từ imports"""
    capabilities = []
    imports = pe_info.get("imports", [])
    
    # 4.4.1. Khả năng mạng
    network_dlls = ['ws2_32.dll', 'wininet.dll', 'winhttp.dll']
    network_functions = ['socket', 'connect', 'send', 'recv', 'http']
    
    has_network = any(
        any(net_dll in imp.get("dll", "").lower() for net_dll in network_dlls) or
        any(net_func in imp.get("function", "").lower() for net_func in network_functions)
        for imp in imports
    )
    if has_network:
        capabilities.append({
            "type": "network",
            "description": "Network communication"
        })
    
    # 4.4.2. Khả năng file system
    file_functions = ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile']
    has_file_ops = any(
        any(file_func in imp.get("function", "").lower() for file_func in file_functions)
        for imp in imports
    )
    if has_file_ops:
        capabilities.append({
            "type": "file_system",
            "description": "File system operations"
        })
    
    # Tương tự cho registry, process manipulation...
    
    return capabilities
```

**Ví dụ capabilities**:
```json
[
  {"type": "file_system", "description": "File system operations"},
  {"type": "registry", "description": "Registry manipulation"},
  {"type": "process_manipulation", "description": "Process manipulation"}
]
```

### Kết Quả Bước 4

```python
{
    "hashes": {
        "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
        "md5": "7b106cafd8dd7b2c66de24feda2233ba"
    },
    "strings": [
        "http://192.168.1.100:8080/command",
        "CreateRemoteThread",
        "registry_startup_demo"
    ],
    "pe_info": {
        "machine": 34404,
        "sections": [...],
        "imports": [...],
        "suspicious_features": ["High entropy section (possibly packed)"]
    },
    "capabilities": [
        {"type": "file_system", "description": "File system operations"}
    ]
}
```

---

## Bước 5: EMBER Model - Machine Learning

### Code Implementation

**File**: `backend/app/ml/ember_model.py`

### Nguồn Gốc Threshold 0.8336

**Vị trí trong code**: `backend/app/ml/ember_model.py:29`

```python
self.threshold = 0.8336  # Ngưỡng EMBER chuẩn tại 1% FPR
```

**Giải thích**:
- **0.8336** là threshold được sử dụng trong EMBER model chuẩn
- **1% FPR** (False Positive Rate): Tại threshold này, model chỉ có 1% khả năng nhận diện sai file sạch là malware
- **Nguồn gốc**: Giá trị này được lấy từ EMBER paper và benchmark của Endgame (tác giả EMBER)
- **Hardcoded**: Giá trị được hardcode trong code, không được tính toán động
- **Ý nghĩa**: 
  - Score >= 0.8336 → Malware (99% chính xác)
  - Score < 0.8336 → Clean (có thể có 1% false negative)

### 5.1. Kiểm Tra PE File

```python
def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
    """Kiểm tra file có phải PE file không"""
    with open(file_path, 'rb') as f:
        header = f.read(2)  # Đọc 2 bytes đầu
        if header == b'MZ':  # PE signature
            # Kiểm tra PE header ở offset 0x3C
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
            f.seek(pe_offset)
            pe_signature = f.read(2)
            if pe_signature == b'PE':
                return True, None
    return False, "Invalid PE header"
```

### 5.2. Extract Features

**File**: `backend/app/ml/features.py`

```python
def feature_vector(self, bytez: bytes) -> np.ndarray:
    """Trích xuất 2381 features từ PE file"""
    # 5.2.1. Load ember library
    if not self._extractor:
        raise ValueError("EMBER extractor not available")
    
    # 5.2.2. Sử dụng PEFeatureExtractor từ ember library
    features = self._extractor.feature_vector(bytez, version=self.feature_version)
    # Trả về numpy array với 2381 features
    
    return features
```

**2381 Features bao gồm**:
- **Histogram features** (256): Tần suất xuất hiện của mỗi byte (0-255)
- **Byte entropy** (256): Entropy của từng byte
- **String features** (1024): Thống kê về strings (length, printable, etc.)
- **General features** (10): File size, entry point, etc.
- **Header features** (92): PE header information
- **Section features** (1000): Thống kê về sections
- **Import features** (128): Thống kê về imports
- **Export features** (128): Thống kê về exports
- **Data directories** (128): Thống kê về data directories

**Ví dụ feature extraction**:
```python
# Đọc file
with open(filepath, 'rb') as f:
    bytez = f.read()

# Extract features
extractor = EmberFeatureExtractor()
features = extractor.feature_vector(bytez)
# features.shape = (2381,)
# features.dtype = float32
```

### 5.3. Predict với LightGBM

```python
def predict(self, file_path: str) -> Dict[str, Any]:
    """Dự đoán file có phải malware không"""
    # 5.3.1. Kiểm tra PE file
    is_pe, pe_error = self.is_pe_file(file_path)
    if not is_pe:
        return {
            "error": "File is not a valid PE file",
            "is_malware": False,
            "score": 0.0
        }
    
    # 5.3.2. Extract features
    with open(file_path, 'rb') as f:
        bytez = f.read()
    
    features = self.extractor.feature_vector(bytez)
    # features.shape = (2381,)
    
    # 5.3.3. Predict với LightGBM model
    score = self.model.predict(features.reshape(1, -1))[0]
    # score là float từ 0.0 đến 1.0
    
    # 5.3.4. So sánh với threshold
    threshold = 0.8336  # Ngưỡng EMBER chuẩn tại 1% FPR (False Positive Rate)
    # Nguồn: Giá trị này được lấy từ EMBER paper/benchmark
    # Tại threshold 0.8336, model có False Positive Rate = 1% (chỉ 1% file sạch bị nhận diện sai là malware)
    # Được hardcode trong: backend/app/ml/ember_model.py:29
    is_malware = score >= threshold
    
    return {
        "is_malware": is_malware,
        "score": float(score),
        "threshold": threshold
    }
```

**Ví dụ kết quả**:
```python
{
    "is_malware": False,  # score < threshold
    "score": 0.000019,    # Rất thấp → file sạch
    "threshold": 0.8336
}
```

hoặc

```python
{
    "is_malware": True,   # score >= threshold
    "score": 0.9234,      # Cao → malware
    "threshold": 0.8336
}
```

### Kết Quả Bước 5

```python
{
    "type": "model",
    "subtype": "ember",
    "message": "[CLEAN] EMBER analysis (Score: 0.000019, Threshold: 0.8336)",
    "score": 0.000019,
    "threshold": 0.8336
}
```

---

## Bước 6: Tổng Hợp Kết Quả

### Code Implementation

**File**: `backend/app/services/analyzer_service.py`

### 6.1. Thu Thập Tất Cả Kết Quả

```python
async def analyze_and_save(self, filepath: str, filename: str, scan_modules: List[str] = None):
    start_time = time.time()
    
    # 6.1.1. Phân tích với các modules
    results = await self.analyze_single_file(filepath, scan_modules)
    # results chứa:
    # - Hash results (nếu có)
    # - YARA results
    # - EMBER results
    
    # 6.1.2. Phân tích tĩnh (luôn chạy)
    static_analysis = self.analyze_with_static_analyzer(filepath)
    # static_analysis chứa:
    # - PE info
    # - Suspicious strings
    # - Capabilities
    
    elapsed = time.time() - start_time
```

### 6.2. Xác Định Malware

```python
# 6.2.1. Logic xác định malware
malware_detected = any(
    result.get("type") in ["hash", "yara", "model"] 
    for result in results
)

# Giải thích:
# - "hash": Hash match trong database → malware
# - "yara": YARA rule match → malware
# - "model": EMBER score >= threshold → malware
# - "ember_error", "yara_error", "clean": KHÔNG phải malware
```

**Ví dụ logic**:
```python
results = [
    {
        "type": "yara",  # ← Đây là malware indicator
        "rule_count": 15
    },
    {
        "type": "model",
        "subtype": "ember",
        "score": 0.000019,  # < threshold → không phải malware
        "is_malware": False
    }
]

# malware_detected = True (vì có "yara" type)
```

### 6.3. Chuẩn Bị Dữ Liệu Lưu Database

```python
# 6.3.1. Extract YARA matches chi tiết
yara_matches_for_db = []
for result in results:
    if result.get("type") == "yara" and result.get("detailed_matches"):
        yara_matches_for_db.extend(result.get("detailed_matches", []))

# 6.3.2. Tạo analysis_data
analysis_data = {
    'filename': filename,                    # "malware.exe"
    'sha256': sha256,                        # "80b4182a..."
    'md5': md5,                              # "7b106caf..."
    'file_size': file_size,                  # 1691648 bytes
    'upload_time': datetime.now(),
    'analysis_time': elapsed,                 # 3.26 seconds
    'malware_detected': malware_detected,     # True/False
    'yara_matches': yara_matches_for_db,     # List of matches
    'pe_info': static_analysis.get("pe_info"),
    'suspicious_strings': static_analysis.get("strings", [])[:20],
    'capabilities': static_analysis.get("capabilities", []),
    'results': results  # Tất cả kết quả từ các modules
}
```

### Kết Quả Bước 6

```python
{
    "filename": "malware.exe",
    "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
    "md5": "7b106cafd8dd7b2c66de24feda2233ba",
    "file_size": 1691648,
    "analysis_time": 3.26,
    "malware_detected": True,  # Vì có YARA matches
    "yara_matches": [
        {
            "rule_name": "DebuggerException__SetConsoleCtrl",
            "tags": ["AntiDebug"],
            "matched_strings": [...]
        }
    ],
    "pe_info": {...},
    "suspicious_strings": [...],
    "results": [
        {"type": "yara", "rule_count": 15},
        {"type": "model", "subtype": "ember", "score": 0.000019}
    ]
}
```

---

## Bước 7: Lưu Database

### Code Implementation

**File**: `backend/app/services/analysis_service.py`

### 7.1. Insert Analysis

```python
async def create(analysis_data: Dict[str, Any]) -> Optional[int]:
    # 7.1.1. Kết nối database
    pool = await get_db_connection()
    conn = await pool.acquire()
    
    async with conn.cursor() as cursor:
        # 7.1.2. Insert vào bảng analyses
        sql = """
            INSERT INTO analyses (
                filename, sha256, md5, file_size, upload_time,
                analysis_time, malware_detected, yara_matches,
                pe_info, suspicious_strings, capabilities, results
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            analysis_data.get('filename'),
            analysis_data.get('sha256'),
            analysis_data.get('md5'),
            analysis_data.get('file_size'),
            analysis_data.get('upload_time'),
            analysis_data.get('analysis_time', 0.0),
            analysis_data.get('malware_detected', False),
            json.dumps(analysis_data.get('yara_matches', [])),  # JSON string
            json.dumps(analysis_data.get('pe_info')),            # JSON string
            json.dumps(analysis_data.get('suspicious_strings', [])),  # JSON string
            json.dumps(analysis_data.get('capabilities', [])),   # JSON string
            json.dumps(analysis_data.get('results', []))         # JSON string
        )
        
        await cursor.execute(sql, values)
        analysis_id = cursor.lastrowid  # Lấy ID vừa insert
```

### 7.2. Insert YARA Matches

```python
# 7.2.1. Insert từng YARA match vào bảng yara_matches
yara_matches = analysis_data.get('yara_matches', [])
for match in yara_matches:
    match_sql = """
        INSERT INTO yara_matches (
            analysis_id, rule_name, tags, description, 
            author, reference, matched_strings
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    
    await cursor.execute(match_sql, (
        analysis_id,
        match.get('rule_name'),
        ', '.join(match.get('tags', [])),  # "AntiDebug, DebuggerException"
        match.get('description'),
        match.get('author'),
        match.get('reference'),
        json.dumps(match.get('matched_strings', []))  # JSON string
    ))
```

### 7.3. Commit Transaction

```python
await conn.commit()  # Lưu tất cả thay đổi
return analysis_id  # Trả về ID để frontend có thể navigate
```

### Kết Quả Bước 7

- Analysis được lưu với `id = 123`
- 15 YARA matches được lưu vào bảng `yara_matches`
- Tất cả dữ liệu được lưu dưới dạng JSON trong các cột TEXT

---

## Bước 8: Trả Response

### Code Implementation

**File**: `backend/app/api/v1/routes/scan.py`

### 8.1. Tạo Response Object

```python
result = ScanResult(
    filename=file.filename,                    # "malware.exe"
    sha256=analysis_data.get("sha256"),        # "80b4182a..."
    md5=analysis_data.get("md5"),              # "7b106caf..."
    yara_matches=analysis_data.get("yara_matches", []),
    pe_info=analysis_data.get("pe_info"),
    suspicious_strings=analysis_data.get("suspicious_strings", []),
    capabilities=analysis_data.get("capabilities", []),
    malware_detected=analysis_data.get("malware_detected", False),
    analysis_time=analysis_data.get("analysis_time", 0.0),
    results=analysis_data.get("results", [])
)

return result  # FastAPI tự động serialize thành JSON
```

### 8.2. JSON Response

```json
{
  "filename": "malware.exe",
  "sha256": "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68",
  "md5": "7b106cafd8dd7b2c66de24feda2233ba",
  "yara_matches": [
    {
      "rule_name": "DebuggerException__SetConsoleCtrl",
      "tags": ["AntiDebug", "DebuggerException"],
      "description": "Detects debugger evasion",
      "matched_strings": [
        {
          "identifier": "$s1",
          "offset": 1024,
          "data": "4d5a9000",
          "data_preview": "MZ..."
        }
      ]
    }
  ],
  "pe_info": {
    "machine": 34404,
    "sections": [...],
    "imports": [...]
  },
  "suspicious_strings": [
    "http://192.168.1.100:8080/command",
    "CreateRemoteThread"
  ],
  "malware_detected": true,
  "analysis_time": 3.26,
  "results": [
    {
      "type": "yara",
      "rule_count": 15,
      "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug)..."
    },
    {
      "type": "model",
      "subtype": "ember",
      "score": 0.000019,
      "threshold": 0.8336
    }
  ]
}
```

### 8.3. Frontend Nhận Response

**File**: `frontend/src/hooks/useScan.ts`

```typescript
const scan = async (file: File, scanType: ScanType = 'full') => {
  const response = await axiosClient.post(endpoint, formData)
  setResult(response)  // Lưu vào state
}
```

**File**: `frontend/src/pages/Upload/Upload.tsx`

```typescript
// Navigate đến detail page
if (result?.id) {
  navigate(`/analyses/${result.id}`)
}
```

### 8.4. Frontend Hiển Thị

**File**: `frontend/src/pages/AnalysisDetail/AnalysisDetail.tsx`

```typescript
// Hiển thị YARA matches
{analysis.yara_matches?.map((match) => (
  <div key={match.id}>
    <h3>{match.rule_name}</h3>
    <p>Tags: {match.tags.join(', ')}</p>
    <p>Description: {match.description}</p>
    {match.matched_strings?.map((str) => (
      <div key={str.offset}>
        Offset: 0x{Number(str.offset).toString(16)}
        Data: {str.data_preview}
      </div>
    ))}
  </div>
))}

// Hiển thị EMBER score
{analysis.results?.find(r => r.type === 'model') && (
  <div>
    EMBER Score: {emberResult.score.toFixed(6)}
    Threshold: {emberResult.threshold}
    {emberResult.score >= emberResult.threshold ? 'MALWARE' : 'CLEAN'}
  </div>
)}
```

---

## Ví Dụ Thực Tế

### File: `malware.exe` (1.61 MB)

#### Bước 1: Upload
- File được lưu tại: `uploads/malware.exe`
- Size: 1,691,648 bytes

#### Bước 2: Hash
```python
sha256 = "80b4182a4fef7b112a87a20d54b8de989d5243edb6b8045b118c976f41a1fd68"
md5 = "7b106cafd8dd7b2c66de24feda2233ba"
```

#### Bước 3: YARA Scan
- **15 rules matched**:
  1. `DebuggerException__SetConsoleCtrl` (tags: AntiDebug)
  2. `anti_dbg` (tags: AntiDebug)
  3. `IsPE64` (tags: PECheck)
  4. `IsPacked` (tags: PECheck) - Entropy Check
  5. `HasOverlay` (tags: PECheck)
  6. ... (10 rules khác)

#### Bước 4: Static Analysis
- **PE Info**:
  - Machine: 34404 (x64)
  - Sections: 7 sections (.text, .rdata, .data, .pdata, .rsrc, .reloc)
  - Imports: 150+ functions từ KERNEL32.dll, USER32.dll, ADVAPI32.dll
  - Suspicious feature: "High entropy section (possibly packed)"
  
- **Suspicious Strings** (8 strings):
  - `Py_DecodeLocale`
  - `PyUnicode_Decode`
  - `registry_startup_demo`
  - `base64`
  - `email.base64mime`

#### Bước 5: EMBER Prediction
- **Features extracted**: 2381 features
- **Score**: 0.000019 (rất thấp)
- **Threshold**: 0.8336
- **Result**: `is_malware = False` (score < threshold)

#### Bước 6: Tổng Hợp
```python
malware_detected = True  # Vì có YARA matches (type="yara")
```

**Logic**:
- YARA matches → `malware_detected = True`
- EMBER score thấp → Không ảnh hưởng (vì đã có YARA match)

#### Bước 7: Lưu Database
- `analysis_id = 123`
- 15 YARA matches được lưu vào `yara_matches` table

#### Bước 8: Response
```json
{
  "id": 123,
  "filename": "malware.exe",
  "sha256": "80b4182a...",
  "malware_detected": true,
  "yara_matches": [...],
  "pe_info": {...},
  "analysis_time": 3.26
}
```

---

## Tóm Tắt Logic Quyết Định

### Quy Tắc Xác Định Malware

```python
malware_detected = any(
    result.get("type") in ["hash", "yara", "model"]
    for result in results
)
```

**Giải thích**:
1. **Hash match**: File hash có trong malware database → `malware_detected = True`
2. **YARA match**: Bất kỳ YARA rule nào match → `malware_detected = True`
3. **EMBER score >= threshold**: Score >= 0.8336 → `malware_detected = True`
4. **Tất cả đều clean**: Không có hash/yara/model match → `malware_detected = False`

### Thứ Tự Ưu Tiên

1. **YARA** có độ ưu tiên cao nhất (signature-based, chính xác)
2. **Hash** có độ ưu tiên cao (file đã biết)
3. **EMBER** có độ ưu tiên thấp hơn (ML prediction, có thể false positive)

### Kết Hợp Kết Quả

- **YARA + EMBER clean**: Vẫn là malware (YARA có ưu tiên cao hơn)
- **YARA clean + EMBER malware**: Là malware (EMBER phát hiện)
- **Cả hai đều clean**: File sạch

---

## Thời Gian Xử Lý

### Breakdown Thời Gian

- **Hash calculation**: ~0.1-0.3 giây (tùy file size)
- **YARA scan**: ~0.5-2 giây (tùy số rules match)
- **Static analysis**: ~0.5-1 giây (parse PE, extract strings)
- **EMBER prediction**: ~1-3 giây (extract features + predict)
- **Database save**: ~0.1-0.2 giây
- **Tổng cộng**: ~2-6 giây cho một file

### Tối Ưu Hóa

- YARA rules được compile sẵn khi khởi động
- EMBER model được load sẵn khi khởi động
- Database connection pooling
- File được xóa ngay sau khi xử lý

---

**Tài liệu này giải thích chi tiết từng bước trong quá trình phân tích file malware, từ khi upload đến khi hiển thị kết quả trên giao diện.**

