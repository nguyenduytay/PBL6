# Giải Thích Chi Tiết Các Thông Số Trong Kết Quả Phân Tích

## Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Thông Số Cơ Bản](#thông-số-cơ-bản)
3. [Thông Số Phân Tích](#thông-số-phân-tích)
4. [PE Info (Thông Tin PE File)](#pe-info-thông-tin-pe-file)
5. [Suspicious Strings](#suspicious-strings)
6. [Results (Kết Quả Từng Module)](#results-kết-quả-từng-module)
7. [Ví Dụ Phân Tích File Cụ Thể](#ví-dụ-phân-tích-file-cụ-thể)

---

## Tổng Quan

Kết quả phân tích là một object JSON chứa tất cả thông tin về file đã được phân tích, bao gồm:
- Thông tin cơ bản (filename, size, hashes)
- Kết quả từ các module (YARA, EMBER, Hash)
- Thông tin PE file (nếu là PE)
- Suspicious strings
- Capabilities

**Ví dụ kết quả**:
```json
{
  "id": 1422,
  "filename": "encryption.exe",
  "sha256": "7dd763c0ccce16c0f8a3935ec55f842f8175a5a5dd28fd1ccb4e234d89746597",
  "malware_detected": 1,
  "analysis_time": 5.75542,
  "pe_info": {...},
  "suspicious_strings": [...],
  "results": [...],
  "yara_matches": []
}
```

---

## Thông Số Cơ Bản

### 1. `id` (1422)

**Giải thích**: ID duy nhất của analysis trong database

**Cách lấy**:
```python
# File: backend/app/services/analysis_service.py (dòng 68-69)
await cursor.execute(sql, values)
analysis_id = cursor.lastrowid  # Lấy ID vừa insert
```

**Vị trí code**: `backend/app/services/analysis_service.py:69`

**Mục đích**: Để truy vấn, cập nhật, xóa analysis sau này

---

### 2. `filename` ("encryption.exe")

**Giải thích**: Tên file được upload

**Cách lấy**:
```python
# File: backend/app/api/v1/routes/scan.py (dòng 24)
async def scan_file(file: UploadFile = File(...)):
    filename = file.filename  # "encryption.exe"
```

**Vị trí code**: `backend/app/api/v1/routes/scan.py:24`

**Lưu vào database**:
```python
# File: backend/app/services/analyzer_service.py (dòng 170)
analysis_data = {
    'filename': filename,  # "encryption.exe"
    # ...
}
```

---

### 3. `file_size` (10132469 bytes = ~9.66 MB)

**Giải thích**: Kích thước file tính bằng bytes

**Cách lấy**:
```python
# File: backend/app/services/analyzer_service.py (dòng 154)
import os
file_size = os.path.getsize(filepath) if os.path.exists(filepath) else None
# file_size = 10132469 (bytes)
```

**Vị trí code**: `backend/app/services/analyzer_service.py:154`

**Công thức**: `os.path.getsize()` trả về số bytes của file

**Ví dụ**: 10132469 bytes = 10,132,469 bytes = ~9.66 MB

---

### 4. `sha256` ("7dd763c0ccce16c0f8a3935ec55f842f8175a5a5dd28fd1ccb4e234d89746597")

**Giải thích**: SHA256 hash của file (64 ký tự hex)

**Cách lấy**:
```python
# File: backend/app/services/hash_service.py (dòng 10-22)
def sha256_hash(filepath: str) -> Optional[str]:
    with open(filepath, 'rb') as f:
        file_content = f.read()  # Đọc toàn bộ file
        return hashlib.sha256(file_content).hexdigest()
```

**Vị trí code**: `backend/app/services/hash_service.py:10-22`

**Công thức**:
1. Đọc toàn bộ file vào memory
2. Tính SHA256 hash bằng `hashlib.sha256()`
3. Chuyển sang hex string (64 ký tự)

**Sử dụng**:
- Tạo infoUrl: `https://bazaar.abuse.ch/sample/{sha256}/`
- Lưu vào database để tra cứu
- So sánh với malware database

---

### 5. `md5` ("1be785c147828c47ff780599c34df78e")

**Giải thích**: MD5 hash của file (32 ký tự hex)

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 101-120)
def _calculate_hashes(self, filepath: str) -> Dict[str, Optional[str]]:
    import hashlib
    
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)
    
    return {
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest()  # "1be785c147828c47ff780599c34df78e"
    }
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:101-120`

**Lấy trong AnalyzerService**:
```python
# File: backend/app/services/analyzer_service.py (dòng 156)
md5 = static_analysis.get("hashes", {}).get("md5")
```

**Công thức**: Tương tự SHA256, nhưng dùng `hashlib.md5()`

---

### 6. `upload_time` ("2025-12-21T00:10:38")

**Giải thích**: Thời gian file được upload (ISO format)

**Cách lấy**:
```python
# File: backend/app/services/analyzer_service.py (dòng 174)
from datetime import datetime
analysis_data = {
    'upload_time': datetime.now(),  # 2025-12-21 00:10:38
    # ...
}
```

**Vị trí code**: `backend/app/services/analyzer_service.py:174`

**Format**: ISO 8601 format khi serialize thành JSON

---

### 7. `created_at` ("2025-12-21T00:10:38")

**Giải thích**: Thời gian analysis được tạo trong database

**Cách lấy**:
```python
# File: backend/app/core/database.py (dòng 134)
CREATE TABLE IF NOT EXISTS analyses (
    # ...
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    # ...
)
```

**Vị trí code**: `backend/app/core/database.py:134`

**Mặc định**: MySQL tự động set `CURRENT_TIMESTAMP` khi insert

---

## Thông Số Phân Tích

### 8. `analysis_time` (5.75542 giây)

**Giải thích**: Thời gian phân tích file (tính bằng giây)

**Cách lấy**:
```python
# File: backend/app/services/analyzer_service.py (dòng 137-143)
import time

start_time = time.time()  # Bắt đầu đo thời gian

# Phân tích file
results = await self.analyze_single_file(filepath, scan_modules)
static_analysis = self.analyze_with_static_analyzer(filepath)

elapsed = time.time() - start_time  # 5.75542 giây
```

**Vị trí code**: `backend/app/services/analyzer_service.py:137-143`

**Công thức**: `elapsed = end_time - start_time`

**Bao gồm**:
- Hash calculation (~0.1-0.3s)
- YARA scan (~0.5-2s)
- Static analysis (~0.5-1s)
- EMBER prediction (~1-3s)
- Database save (~0.1-0.2s)

**Ví dụ**: 5.75542 giây = 5 giây 755 milliseconds

---

### 9. `malware_detected` (1 = true)

**Giải thích**: Có phát hiện malware không (1 = true, 0 = false)

**Cách xác định**:
```python
# File: backend/app/services/analyzer_service.py (dòng 145-151)
# Xác định có malware không
# Chỉ các type "hash", "yara", "model" được coi là malware
# "ember_error", "yara_error", "clean" không phải malware
malware_detected = any(
    result.get("type") in ["hash", "yara", "model"] 
    for result in results
)
```

**Vị trí code**: `backend/app/services/analyzer_service.py:148-151`

**Logic**:
- Nếu có result với `type="hash"` → `malware_detected = True`
- Nếu có result với `type="yara"` → `malware_detected = True`
- Nếu có result với `type="model"` (và `is_malware=True`) → `malware_detected = True`
- Nếu chỉ có `type="clean"` hoặc `type="ember_error"` → `malware_detected = False`

**Trong ví dụ**:
- `results = [{type: "model", score: 0.0029065, ...}]`
- `type="model"` → `malware_detected = True` (nhưng score < threshold nên thực tế không phải malware)
- **Lưu ý**: Logic này có thể cần điều chỉnh vì score < threshold nhưng vẫn set `malware_detected = True`

---

### 10. `yara_matches` ([] - rỗng)

**Giải thích**: Danh sách YARA rule matches (rỗng = không có match)

**Cách lấy**:
```python
# File: backend/app/services/analyzer_service.py (dòng 158-166)
# Extract detailed YARA matches từ results
yara_matches_for_db = []
for result in results:
    if result.get("type") == "yara" and result.get("detailed_matches"):
        yara_matches_for_db.extend(result.get("detailed_matches", []))

# Nếu không có detailed_matches, fallback về static_analysis
if not yara_matches_for_db:
    yara_matches_for_db = static_analysis.get("yara_matches", [])
```

**Vị trí code**: `backend/app/services/analyzer_service.py:158-166`

**Trong ví dụ**: `[]` (rỗng) → Không có YARA rule nào match

**Nếu có matches**:
```json
[
  {
    "rule_name": "DebuggerException__SetConsoleCtrl",
    "tags": ["AntiDebug"],
    "description": "Detects debugger evasion",
    "matched_strings": [...]
  }
]
```

---

## PE Info (Thông Tin PE File)

### 11. `pe_info.machine` (34404)

**Giải thích**: Kiến trúc CPU (34404 = x64, 332 = x86)

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 211)
pe = pefile.PE(filepath, fast_load=True)
pe_info = {
    "machine": pe.FILE_HEADER.Machine,  # 34404
    # ...
}
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:211`

**Giá trị**:
- `34404` (0x8664) = IMAGE_FILE_MACHINE_AMD64 (x64)
- `332` (0x14C) = IMAGE_FILE_MACHINE_I386 (x86)

**Nguồn**: PE file header (IMAGE_FILE_HEADER.Machine)

---

### 12. `pe_info.timestamp` (1766187871)

**Giải thích**: Timestamp khi file được compile (Unix timestamp)

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 212)
pe_info = {
    "timestamp": pe.FILE_HEADER.TimeDateStamp,  # 1766187871
    # ...
}
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:212`

**Chuyển đổi**:
```python
from datetime import datetime
timestamp = 1766187871
dt = datetime.fromtimestamp(timestamp)
# 2025-12-21 00:10:38 (UTC)
```

**Nguồn**: PE file header (IMAGE_FILE_HEADER.TimeDateStamp)

---

### 13. `pe_info.sections[]`

**Giải thích**: Danh sách các sections trong PE file

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 219-235)
# Phân tích sections
for section in pe.sections:
    section_data = {
        "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),  # ".text"
        "virtual_address": section.VirtualAddress,        # 4096
        "virtual_size": section.Misc_VirtualSize,        # 184752
        "raw_size": section.SizeOfRawData,               # 184832
        "entropy": self._calculate_entropy(section.get_data())  # 6.483896
    }
    pe_info["sections"].append(section_data)
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:219-235`

**Các thông số trong section**:

#### 13.1. `name` (".text", ".rdata", ".data", ...)

**Giải thích**: Tên section

**Cách lấy**:
```python
section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
```

**Các section thường gặp**:
- `.text`: Code section (chứa mã thực thi)
- `.rdata`: Read-only data (chứa constants, strings)
- `.data`: Initialized data (chứa global variables)
- `.rsrc`: Resources (chứa icons, images, strings)
- `.reloc`: Relocations (chứa relocation table)

#### 13.2. `entropy` (6.483896, 7.350146, ...)

**Giải thích**: Entropy của section (độ ngẫu nhiên của data)

**Cách tính**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 269-282)
def _calculate_entropy(self, data: bytes) -> float:
    """Tính Shannon entropy của data"""
    import math
    if not data:
        return 0.0
    
    entropy = 0.0
    for byte in range(256):
        count = data.count(byte)
        if count > 0:
            p = count / len(data)  # Xác suất xuất hiện
            entropy -= p * math.log2(p)  # Shannon entropy
    
    return entropy
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:269-282`

**Công thức Shannon Entropy**:
```
H(X) = -Σ p(x) * log2(p(x))
```

**Giải thích**:
- **Entropy thấp (0-4)**: Data có cấu trúc, dễ nén (text, code)
- **Entropy trung bình (4-7)**: Data bình thường
- **Entropy cao (7-8)**: Data ngẫu nhiên, có thể bị pack/encrypt

**Trong ví dụ**:
- `.text`: 6.483896 (trung bình) → Code bình thường
- `.rsrc`: 7.350146 (cao) → Có thể bị pack → `suspicious_features: ["High entropy section (possibly packed)"]`

#### 13.3. `raw_size` (184832, 79872, ...)

**Giải thích**: Kích thước section trên disk (bytes)

**Cách lấy**:
```python
section.SizeOfRawData  # 184832 bytes
```

**Nguồn**: PE section header (IMAGE_SECTION_HEADER.SizeOfRawData)

#### 13.4. `virtual_size` (184752, 79578, ...)

**Giải thích**: Kích thước section trong memory (bytes)

**Cách lấy**:
```python
section.Misc_VirtualSize  # 184752 bytes
```

**Nguồn**: PE section header (IMAGE_SECTION_HEADER.Misc.VirtualSize)

**Khác biệt**: `virtual_size` có thể khác `raw_size` do alignment

#### 13.5. `virtual_address` (4096, ...)

**Giải thích**: Địa chỉ ảo của section trong memory

**Cách lấy**:
```python
section.VirtualAddress  # 4096 (0x1000)
```

**Nguồn**: PE section header (IMAGE_SECTION_HEADER.VirtualAddress)

---

### 14. `pe_info.imports[]` ([] - rỗng)

**Giải thích**: Danh sách các hàm được import từ DLLs

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 237-249)
# Phân tích imports (các hàm được import)
try:
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')  # "KERNEL32.dll"
            for imp in entry.imports:
                if imp.name:
                    pe_info["imports"].append({
                        "dll": dll_name,
                        "function": imp.name.decode('utf-8', errors='ignore')  # "CreateFileW"
                    })
except:
    pass
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:237-249`

**Trong ví dụ**: `[]` (rỗng) → File này có thể không có imports hoặc là PyInstaller (imports được load động)

**Nếu có imports**:
```json
[
  {"dll": "KERNEL32.dll", "function": "CreateFileW"},
  {"dll": "KERNEL32.dll", "function": "WriteFile"},
  {"dll": "USER32.dll", "function": "ShowWindow"}
]
```

---

### 15. `pe_info.exports[]` ([] - rỗng)

**Giải thích**: Danh sách các hàm được export (thường là DLL)

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 251-258)
# Phân tích exports (các hàm được export)
try:
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                pe_info["exports"].append(exp.name.decode('utf-8', errors='ignore'))
except:
    pass
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:251-258`

**Trong ví dụ**: `[]` (rỗng) → File .exe thường không có exports (chỉ DLL mới có)

---

### 16. `pe_info.suspicious_features[]` (["High entropy section (possibly packed)"])

**Giải thích**: Các đặc điểm đáng ngờ của PE file

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 231-233)
# Kiểm tra entropy cao (có thể bị pack)
if section_data["entropy"] > 7.0:
    pe_info["suspicious_features"].append("High entropy section (possibly packed)")
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:231-233`

**Trong ví dụ**: 
- `.rsrc` section có entropy = 7.350146 > 7.0
- → Thêm "High entropy section (possibly packed)" vào `suspicious_features`

**Ý nghĩa**: File có thể bị pack/encrypt để tránh phát hiện

---

## Suspicious Strings

### 17. `suspicious_strings[]` (List các strings đáng ngờ)

**Giải thích**: Danh sách các strings đáng ngờ được extract từ file

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 122-167)
def _extract_strings(self, content: bytes) -> List[str]:
    """Trích xuất strings có thể đọc được từ binary"""
    strings = []
    seen = set()
    
    # 1. Trích xuất ASCII strings (>= 4 ký tự)
    current_string = []
    for byte in content:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= 4:
                s = ''.join(current_string)
                if len(s) <= 200 and s not in seen:
                    seen.add(s)
                    # Kiểm tra có đáng ngờ không
                    if self._is_suspicious_string(s):
                        strings.append(s)
            current_string = []
    
    # 2. Trích xuất Unicode strings (UTF-16 LE)
    # ...
    
    # 3. Sắp xếp và giới hạn
    strings.sort(key=len, reverse=True)
    return strings[:100]  # Giới hạn 100 strings
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:122-167`

**Lưu vào database**:
```python
# File: backend/app/services/analyzer_service.py (dòng 179)
'suspicious_strings': static_analysis.get("strings", [])[:20]  # Limit 20
```

**Trong ví dụ**:
```json
[
  "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"...",
  "import sys; sys.stdout.flush(); ...",
  "Could not load PyInstaller's embedded PKG archive...",
  // ... 17 strings khác
]
```

**Giải thích các strings trong ví dụ**:
1. **XML manifest strings**: File có Windows manifest (bình thường)
2. **Python strings**: File được build bằng PyInstaller (Python executable)
3. **PyInstaller error messages**: Các thông báo lỗi từ PyInstaller

**Tại sao đáng ngờ**:
- Chứa từ khóa "PyInstaller" → Có thể là Python malware
- Chứa "import sys" → Python code
- Có thể là malware được viết bằng Python và pack bằng PyInstaller

---

## Results (Kết Quả Từng Module)

### 18. `results[]` ([{type: "model", score: 0.0029065, ...}])

**Giải thích**: Danh sách kết quả từ các module phân tích (Hash, YARA, EMBER)

**Cách lấy**:
```python
# File: backend/app/services/analyzer_service.py (dòng 140)
results = await self.analyze_single_file(filepath, scan_modules)
# results = [
#     {type: "model", subtype: "ember", score: 0.0029065, ...}
# ]
```

**Vị trí code**: `backend/app/services/analyzer_service.py:140`

**Lưu vào database**:
```python
# File: backend/app/services/analyzer_service.py (dòng 181)
analysis_data = {
    'results': results  # Lưu toàn bộ results
}
```

**Trong ví dụ**:
```json
[
  {
    "type": "model",
    "subtype": "ember",
    "score": 0.0029065092324246865,
    "threshold": 0.8336,
    "message": "[CLEAN] EMBER analysis (Score: 0.002906, Threshold: 0.8336)",
    "infoUrl": null
  }
]
```

**Giải thích từng field**:

#### 18.1. `type` ("model")

**Giải thích**: Loại kết quả (hash, yara, model, clean, ember_error)

**Các giá trị**:
- `"hash"`: Hash match trong database
- `"yara"`: YARA rule match
- `"model"`: EMBER model prediction
- `"clean"`: Không phát hiện gì
- `"ember_error"`: Lỗi khi chạy EMBER
- `"yara_error"`: Lỗi khi chạy YARA

#### 18.2. `subtype` ("ember")

**Giải thích**: Subtype của model (chỉ có khi type="model")

**Giá trị**: `"ember"` (EMBER model)

#### 18.3. `score` (0.0029065092324246865)

**Giải thích**: EMBER score (từ 0.0 đến 1.0)

**Cách lấy**:
```python
# File: backend/app/ml/ember_model.py (dòng 215-216)
score = ember.predict_sample(self.model, bytez, feature_version=2)
score = float(score)  # 0.0029065092324246865
```

**Vị trí code**: `backend/app/ml/ember_model.py:215-216`

**Giải thích**:
- **Score < threshold (0.8336)**: File sạch (trong ví dụ: 0.0029 < 0.8336 → Clean)
- **Score >= threshold**: File có thể là malware

**Trong ví dụ**: 0.0029 rất thấp → File sạch theo EMBER

#### 18.4. `threshold` (0.8336)

**Giải thích**: Ngưỡng EMBER để xác định malware

**Cách lấy**:
```python
# File: backend/app/ml/ember_model.py (dòng 29)
self.threshold = 0.8336  # Ngưỡng EMBER chuẩn tại 1% FPR
```

**Vị trí code**: `backend/app/ml/ember_model.py:29`

**So sánh**:
- `score (0.0029) < threshold (0.8336)` → `is_malware = False`

#### 18.5. `message` ("[CLEAN] EMBER analysis...")

**Giải thích**: Thông báo kết quả

**Cách tạo**:
```python
# File: backend/app/services/analyzer_service.py (dòng 105-114)
if ember_result.get("is_malware"):
    results.append({
        "type": "model",
        "message": f"[MALWARE] EMBER detection (Score: {score:.4f})",
        # ...
    })
else:
    results.append({
        "type": "model",
        "message": f"[CLEAN] EMBER analysis (Score: {score:.4f}, Threshold: {threshold:.4f})",
        # ...
    })
```

**Vị trí code**: `backend/app/services/analyzer_service.py:105-114`

**Trong ví dụ**: `"[CLEAN] EMBER analysis (Score: 0.002906, Threshold: 0.8336)"`

---

## Capabilities

### 19. `capabilities[]` ([] - rỗng)

**Giải thích**: Khả năng của file (network, file system, registry, process manipulation)

**Cách lấy**:
```python
# File: backend/app/services/static_analyzer_impl.py (dòng 284-340)
def _extract_capabilities(self, pe_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Trích xuất khả năng từ thông tin PE"""
    capabilities = []
    imports = pe_info.get("imports", [])
    
    # Kiểm tra khả năng mạng
    network_dlls = ['ws2_32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll']
    network_functions = ['socket', 'connect', 'send', 'recv', 'http', 'download']
    
    has_network = any(
        any(net_dll in imp.get("dll", "").lower() for net_dll in network_dlls) or
        any(net_func in imp.get("function", "").lower() for net_func in network_functions)
        for imp in imports
    )
    if has_network:
        capabilities.append({"type": "network", "description": "Network communication"})
    
    # Tương tự cho file_system, registry, process_manipulation
    # ...
    
    return capabilities
```

**Vị trí code**: `backend/app/services/static_analyzer_impl.py:284-340`

**Trong ví dụ**: `[]` (rỗng) → Vì `imports = []` (không có imports)

**Nếu có capabilities**:
```json
[
  {"type": "network", "description": "Network communication"},
  {"type": "file_system", "description": "File system operations"},
  {"type": "registry", "description": "Registry manipulation"}
]
```

---

## Ví Dụ Phân Tích File Cụ Thể

### File: `encryption.exe`

**Thông số cơ bản**:
- **Filename**: "encryption.exe"
- **Size**: 10,132,469 bytes (~9.66 MB)
- **SHA256**: "7dd763c0ccce16c0f8a3935ec55f842f8175a5a5dd28fd1ccb4e234d89746597"
- **MD5**: "1be785c147828c47ff780599c34df78e"

**Kết quả phân tích**:
- **Analysis time**: 5.75542 giây
- **Malware detected**: 1 (true) - **Nhưng thực tế score < threshold**
- **YARA matches**: [] (không có)
- **EMBER score**: 0.0029065 (rất thấp, < threshold 0.8336)

**PE Info**:
- **Machine**: 34404 (x64)
- **Sections**: 7 sections (.text, .rdata, .data, .pdata, .fptable, .rsrc, .reloc)
- **High entropy**: `.rsrc` section có entropy 7.35 > 7.0 → Có thể bị pack
- **Imports**: [] (rỗng) → Có thể là PyInstaller (load imports động)
- **Exports**: [] (rỗng) → File .exe thường không có exports

**Suspicious Strings**:
- Chứa nhiều strings về PyInstaller
- Chứa Python code ("import sys", "sys.stdout.flush()")
- **Kết luận**: File được build bằng PyInstaller (Python executable)

**Kết luận**:
- **YARA**: Không phát hiện (không có rule match)
- **EMBER**: Score thấp (0.0029) → File sạch
- **Nhưng**: `malware_detected = 1` vì có result với `type="model"` (logic cần điều chỉnh)
- **Thực tế**: File có thể là Python executable (PyInstaller), không phải malware

---

## Tóm Tắt Cách Lấy Các Thông Số

### Thông Số Từ File System

| Thông Số | Cách Lấy | File Code |
|----------|----------|-----------|
| `filename` | `file.filename` | `scan.py:24` |
| `file_size` | `os.path.getsize(filepath)` | `analyzer_service.py:154` |
| `sha256` | `hashlib.sha256(content).hexdigest()` | `hash_service.py:10-22` |
| `md5` | `hashlib.md5(content).hexdigest()` | `static_analyzer_impl.py:101-120` |

### Thông Số Từ Phân Tích

| Thông Số | Cách Lấy | File Code |
|----------|----------|-----------|
| `analysis_time` | `time.time() - start_time` | `analyzer_service.py:137-143` |
| `malware_detected` | `any(result.type in ["hash","yara","model"])` | `analyzer_service.py:148-151` |
| `yara_matches` | `yara_service.scan_file()` | `yara_service.py:23-128` |
| `results` | `analyze_single_file()` | `analyzer_service.py:36-124` |

### Thông Số Từ PE File

| Thông Số | Cách Lấy | File Code |
|----------|----------|-----------|
| `pe_info.machine` | `pe.FILE_HEADER.Machine` | `static_analyzer_impl.py:211` |
| `pe_info.timestamp` | `pe.FILE_HEADER.TimeDateStamp` | `static_analyzer_impl.py:212` |
| `pe_info.sections` | `pe.sections` + entropy calculation | `static_analyzer_impl.py:219-235` |
| `pe_info.imports` | `pe.DIRECTORY_ENTRY_IMPORT` | `static_analyzer_impl.py:237-249` |
| `pe_info.exports` | `pe.DIRECTORY_ENTRY_EXPORT` | `static_analyzer_impl.py:251-258` |
| `pe_info.suspicious_features` | Entropy > 7.0 check | `static_analyzer_impl.py:231-233` |

### Thông Số Từ Static Analyzer

| Thông Số | Cách Lấy | File Code |
|----------|----------|-----------|
| `suspicious_strings` | `_extract_strings()` + `_is_suspicious_string()` | `static_analyzer_impl.py:122-187` |
| `capabilities` | `_extract_capabilities()` từ imports | `static_analyzer_impl.py:284-340` |

### Thông Số Từ EMBER

| Thông Số | Cách Lấy | File Code |
|----------|----------|-----------|
| `results[].score` | `ember.predict_sample()` | `ember_model.py:215-216` |
| `results[].threshold` | `self.threshold = 0.8336` | `ember_model.py:29` |

---

**Tài liệu này giải thích chi tiết từng thông số trong kết quả phân tích và cách lấy được chúng.**

