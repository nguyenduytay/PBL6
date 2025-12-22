# Kiểm Tra File Bằng YARA - Hướng Dẫn Chi Tiết

## Mục Lục

1. [Tổng Quan YARA](#tổng-quan-yara)
2. [Vị Trí Các File Liên Quan](#vị-trí-các-file-liên-quan)
3. [Thư Viện YARA](#thư-viện-yara)
4. [Quy Trình Load YARA Rules](#quy-trình-load-yara-rules)
5. [Quy Trình Quét File](#quy-trình-quét-file)
6. [Lưu Kết Quả Vào Database](#lưu-kết-quả-vào-database)
7. [Trả Về Kết Quả](#trả-về-kết-quả)
8. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

---

## Tổng Quan YARA

**YARA** (Yet Another Recursive Acronym) là công cụ mã nguồn mở để phát hiện malware dựa trên **signature-based detection** (phát hiện dựa trên mẫu).

**Cách hoạt động**:
- YARA sử dụng các **rules** (luật) để mô tả patterns của malware
- Mỗi rule chứa các **strings** (chuỗi) và **conditions** (điều kiện)
- Khi quét file, YARA so khớp file với tất cả rules
- Nếu có rule match → File có thể là malware

**Ví dụ YARA Rule**:
```yara
rule MalwareExample {
    meta:
        description = "Example malware rule"
        author = "Security Team"
    
    strings:
        $s1 = "malicious_string"
        $s2 = { 4D 5A 90 00 }  // MZ header
    
    condition:
        $s1 and $s2
}
```

---

## Vị Trí Các File Liên Quan

### 1. Thư Viện YARA Python

**File**: `backend/requirements.txt`

```python
yara-python==4.5.4
```

**Vị trí**: Dòng 257 trong `requirements.txt`

**Giải thích**: Đây là thư viện Python binding cho YARA engine (C library)

### 2. YARA Rules Files

**Thư mục gốc**: `backend/yara_rules/rules/`

**File chính**: `backend/yara_rules/rules/index.yar`

**Cấu trúc thư mục**:
```
backend/
└── yara_rules/
    └── rules/
        ├── index.yar          # File chính chứa tất cả rules
        └── malware/
            └── Operation_Blockbuster/
                ├── WhiskeyDelta.yara
                ├── general.yara
                ├── cert_wiper.yara
                └── ... (nhiều file .yara khác)
```

**File index.yar**: File này import tất cả các rules từ các file `.yara` khác

### 3. YARA Service

**File**: `backend/app/services/yara_service.py`

**Chức năng**: Service xử lý quét file bằng YARA

### 4. Configuration

**File**: `backend/app/core/config.py`

**Chức năng**: Load và compile YARA rules khi khởi động ứng dụng

**Đường dẫn rules**:
```python
YARA_RULES_PATH: Path = BASE_DIR / "yara_rules" / "rules" / "index.yar"
```

### 5. Analyzer Service

**File**: `backend/app/services/analyzer_service.py`

**Chức năng**: Điều phối quét YARA cùng với các module khác (Hash, EMBER)

### 6. Analysis Service

**File**: `backend/app/services/analysis_service.py`

**Chức năng**: Lưu kết quả YARA matches vào database

### 7. Database Schema

**Bảng `analyses`**: Lưu thông tin phân tích (có cột `yara_matches` JSON)

**Bảng `yara_matches`**: Lưu chi tiết từng YARA match

**File**: `backend/app/core/database.py` (dòng 148-164)

---

## Thư Viện YARA

### 3.1. Import Thư Viện

**File**: `backend/app/services/yara_service.py` (dòng 6)

```python
import yara
```

**File**: `backend/app/core/config.py` (dòng 9)

```python
import yara
```

**Giải thích**: 
- `yara` là module Python binding cho YARA C library
- Được cài đặt qua `pip install yara-python==4.5.4`
- Cung cấp các hàm: `yara.compile()`, `rules.match()`

### 3.2. Kiểm Tra Thư Viện Đã Cài Đặt

**Cách kiểm tra**:
```bash
pip list | grep yara
# Kết quả: yara-python    4.5.4
```

**Hoặc trong Python**:
```python
import yara
print(yara.__version__)  # In ra version
```

### 3.3. Các Hàm Chính Của YARA

1. **`yara.compile()`**: Compile YARA rules từ file
2. **`rules.match()`**: Quét file với compiled rules
3. **`match.rule`**: Tên rule đã match
4. **`match.tags`**: Tags của rule
5. **`match.meta`**: Metadata (description, author, reference)
6. **`match.strings`**: Các strings đã khớp

---

## Quy Trình Load YARA Rules

### 4.1. Khởi Tạo Khi Ứng Dụng Start

**File**: `backend/app/main.py` (dòng 83-92)

```python
# Load YARA rules
try:
    rules = settings.load_yara_rules()
    if rules:
        rule_count = len(list(rules))
        logger.info(f"YARA rules loaded: {rule_count} rules")
    else:
        logger.warning("YARA rules not loaded")
except Exception as e:
    logger.error(f"Error loading YARA rules: {e}")
```

**Giải thích**:
- YARA rules được load **một lần** khi ứng dụng khởi động
- Load thành công → Log số lượng rules
- Load thất bại → Log warning, nhưng ứng dụng vẫn chạy

### 4.2. Chi Tiết Load Rules

**File**: `backend/app/core/config.py` (dòng 95-159)

```python
@classmethod
def load_yara_rules(cls) -> Optional[yara.Rules]:
    """Load YARA rules từ file"""
    global yara_rules
    
    # 4.2.1. Kiểm tra đã load chưa (lazy loading)
    if yara_rules is not None:
        return yara_rules  # Trả về ngay nếu đã load
    
    try:
        settings = cls()
        
        # 4.2.2. Kiểm tra file rules tồn tại
        if settings.YARA_RULES_PATH.exists():
            print(f"[YARA] Loading rules from: {settings.YARA_RULES_PATH}")
            
            # 4.2.3. Compile YARA rules
            try:
                yara_rules = yara.compile(
                    filepath=str(settings.YARA_RULES_PATH),
                    includes=True,  # Load tất cả rules từ includes
                    error_on_warning=False  # Bỏ qua warnings
                )
            except TypeError:
                # Fallback nếu error_on_warning không được support
                try:
                    yara_rules = yara.compile(
                        filepath=str(settings.YARA_RULES_PATH),
                        includes=True
                    )
                except:
                    # Fallback cuối cùng
                    yara_rules = yara.compile(
                        filepath=str(settings.YARA_RULES_PATH)
                    )
            
            # 4.2.4. Đếm số lượng rules
            rule_count = len(list(yara_rules)) if yara_rules else 0
            print(f"[OK] YARA rules loaded: {rule_count} rules")
            return yara_rules
        else:
            # File không tồn tại
            print(f"[WARN] YARA rules file not found: {settings.YARA_RULES_PATH}")
            return None
            
    except yara.SyntaxError as e:
        # Lỗi cú pháp YARA
        print(f"[ERROR] YARA syntax error: {e}")
        return None
    except Exception as e:
        # Lỗi khác
        print(f"[WARN] Warning loading YARA rules: {e}")
        return None
```

**Giải thích từng bước**:

1. **Lazy Loading**: Nếu đã load rồi → Trả về ngay (không load lại)
2. **Kiểm tra file**: Kiểm tra `yara_rules/rules/index.yar` có tồn tại không
3. **Compile rules**: 
   - `yara.compile()` compile tất cả rules từ file
   - `includes=True` → Load tất cả rules từ các file được include
   - `error_on_warning=False` → Bỏ qua warnings (như invalid field "sync")
4. **Đếm rules**: Đếm số lượng rules đã load (ví dụ: 12,159 rules)
5. **Xử lý lỗi**: 
   - Syntax error → Log error
   - File không tồn tại → Log warning
   - Lỗi khác → Log warning, return None

**Ví dụ output**:
```
[YARA] Loading rules from: /app/yara_rules/rules/index.yar
[OK] YARA rules loaded: 12159 rules
```

### 4.3. Khởi Tạo YaraService

**File**: `backend/app/services/yara_service.py` (dòng 12-21)

```python
def __init__(self):
    # 4.3.1. Lấy YARA rules từ settings
    self.rules = settings.get_yara_rules()
    
    # 4.3.2. Kiểm tra rules đã load chưa
    if self.rules:
        try:
            rule_count = len(list(self.rules))
            print(f"[YARA] YaraService initialized with {rule_count} rules")
        except Exception as e:
            print(f"[YARA] WARNING: Could not count rules: {e}")
    else:
        print("[YARA] WARNING: YaraService initialized but no rules loaded!")
```

**Giải thích**:
- `settings.get_yara_rules()` → Lấy rules đã compile (hoặc load nếu chưa)
- Nếu rules = None → Log warning (nhưng service vẫn hoạt động)
- Nếu rules có → Log số lượng rules

---

## Quy Trình Quét File

### 5.1. Gọi YARA Scan

**File**: `backend/app/services/analyzer_service.py` (dòng 58-72)

```python
# 2) Quét YARA - phát hiện malware dựa trên patterns
if "yara" in scan_modules:
    # 5.1.1. Tính SHA256 để tạo infoUrl
    if sha256 is None:
        sha256 = self.hash_service.calculate_hash(filepath)
    
    # 5.1.2. Gọi YARA service để quét file
    yara_results = self.yara_service.scan_file(filepath)
    
    # 5.1.3. Thêm link tham khảo từ bazaar.abuse.ch
    if yara_results and sha256:
        for result in yara_results:
            if result.get("type") == "yara" and not result.get("infoUrl"):
                result["infoUrl"] = f"https://bazaar.abuse.ch/sample/{sha256}/"
    
    # 5.1.4. Thêm kết quả vào danh sách
    results.extend(yara_results)
```

**Giải thích**:
- Chỉ quét YARA nếu `"yara"` có trong `scan_modules`
- Tính SHA256 để tạo link tham khảo
- Gọi `yara_service.scan_file()` để quét
- Thêm infoUrl cho mỗi match
- Thêm kết quả vào `results`

### 5.2. Chi Tiết Scan File

**File**: `backend/app/services/yara_service.py` (dòng 23-128)

```python
def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
    """Scan file với YARA rules"""
    
    # 5.2.1. Kiểm tra rules đã load chưa
    if not self.rules:
        print(f"[YARA] WARNING: YARA rules not loaded, skipping scan for {filepath}")
        return []  # Trả về rỗng nếu không có rules
    
    try:
        print(f"[YARA] Scanning file: {filepath}")
        
        # 5.2.2. Quét file với YARA rules
        matches = self.rules.match(filepath)
        # YARA engine sẽ:
        # - Đọc file từng chunk
        # - So khớp với tất cả 12,159 rules
        # - Trả về list các rules đã match
        
        # 5.2.3. Kiểm tra có match không
        if not matches:
            print(f"[YARA] No matches found for {filepath}")
            return []  # Không có match → Trả về rỗng
        
        print(f"[YARA] Found {len(matches)} matches for {filepath}")
        
        # 5.2.4. Xử lý matches
        results = []
        match_details = []
        
        # Tạo danh sách match đơn giản cho hiển thị
        for match in matches:
            rule_info = str(match.rule)  # Tên rule
            
            # Thêm tags nếu có
            if hasattr(match, 'tags') and match.tags:
                rule_info += f" (tags: {', '.join(match.tags)})"
            
            # Thêm mô tả nếu có
            if hasattr(match, 'meta') and match.meta:
                if 'description' in match.meta:
                    rule_info += f" - {match.meta['description']}"
            
            match_details.append(rule_info)
        
        # 5.2.5. Tạo danh sách match chi tiết để lưu database
        detailed_matches = []
        for match in matches:
            match_obj = {
                "rule_name": str(match.rule),
                "tags": list(match.tags) if hasattr(match, 'tags') and match.tags else [],
                "description": None,
                "author": None,
                "reference": None,
                "matched_strings": []
            }
            
            # Lấy thông tin meta (mô tả, tác giả, tham khảo)
            if hasattr(match, 'meta') and match.meta:
                match_obj["description"] = match.meta.get('description')
                match_obj["author"] = match.meta.get('author')
                match_obj["reference"] = match.meta.get('reference')
            
            # 5.2.6. Lấy các strings đã khớp
            if hasattr(match, 'strings') and match.strings:
                for s in match.strings:
                    # s là yara.StringMatch object
                    string_info = {
                        "identifier": getattr(s, 'identifier', None),  # "$s1"
                        "offset": getattr(s, 'offset', None),           # 1024 (byte offset)
                        "data": None,
                        "data_preview": None
                    }
                    
                    # Lấy data (bytes)
                    data = getattr(s, 'data', None)
                    if data:
                        if isinstance(data, bytes):
                            string_info["data"] = data.hex()  # Chuyển sang hex
                            # Thử decode thành string để preview
                            try:
                                decoded = data.decode('ascii', errors='ignore')
                                if decoded and decoded.isprintable() and len(decoded) > 0:
                                    string_info["data_preview"] = decoded[:100]  # Giới hạn 100 ký tự
                            except:
                                pass
                        else:
                            string_info["data"] = str(data)
                    
                    match_obj["matched_strings"].append(string_info)
            
            detailed_matches.append(match_obj)
        
        # 5.2.7. Tạo result object
        results.append({
            "type": "yara",
            "file": filepath,
            "matches": ", ".join(match_details),  # String đơn giản
            "rule_count": len(matches),
            "detailed_matches": detailed_matches,  # Chi tiết để lưu database
            "infoUrl": None  # Sẽ được điền bởi analyzer service
        })
        
        return results
        
    except Exception as e:
        # 5.2.8. Xử lý lỗi
        print(f"[YARA] ERROR scanning {filepath}: {e}")
        import traceback
        traceback.print_exc()
        return [{
            "type": "yara_error",
            "message": f"Lỗi quét YARA: {str(e)}",
            "infoUrl": None
        }]
```

**Giải thích từng bước**:

1. **Kiểm tra rules**: Nếu không có rules → Trả về rỗng
2. **Quét file**: `self.rules.match(filepath)` → YARA engine quét file
3. **Kiểm tra matches**: Nếu không có match → Trả về rỗng
4. **Xử lý matches**: 
   - Tạo danh sách match đơn giản (cho hiển thị)
   - Tạo danh sách match chi tiết (cho database)
5. **Extract strings**: Lấy các strings đã khớp với offset và data
6. **Tạo result**: Tạo object chứa tất cả thông tin
7. **Xử lý lỗi**: Nếu có lỗi → Trả về error result

**Ví dụ kết quả**:
```python
[
    {
        "type": "yara",
        "file": "uploads/malware.exe",
        "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, anti_dbg, ...",
        "rule_count": 15,
        "detailed_matches": [
            {
                "rule_name": "DebuggerException__SetConsoleCtrl",
                "tags": ["AntiDebug", "DebuggerException"],
                "description": "Detects debugger evasion",
                "author": "Security Team",
                "reference": "https://example.com",
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
        "infoUrl": None
    }
]
```

---

## Lưu Kết Quả Vào Database

### 6.1. Chuẩn Bị Dữ Liệu

**File**: `backend/app/services/analyzer_service.py` (dòng 158-166)

```python
# 6.1.1. Extract detailed YARA matches từ results
yara_matches_for_db = []
for result in results:
    if result.get("type") == "yara" and result.get("detailed_matches"):
        yara_matches_for_db.extend(result.get("detailed_matches", []))

# 6.1.2. Nếu không có detailed_matches, fallback về static_analysis
if not yara_matches_for_db:
    yara_matches_for_db = static_analysis.get("yara_matches", [])
```

**Giải thích**:
- Lấy `detailed_matches` từ YARA results
- Nếu không có → Fallback về static_analysis
- Chuẩn bị để lưu vào database

### 6.2. Lưu Vào Bảng `analyses`

**File**: `backend/app/services/analysis_service.py` (dòng 45-70)

```python
# 6.2.1. Insert vào bảng analyses
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
    # ... các fields khác
)

await cursor.execute(sql, values)
analysis_id = cursor.lastrowid  # Lấy ID vừa insert
```

**Giải thích**:
- Lưu `yara_matches` dưới dạng JSON string vào cột `yara_matches`
- Lấy `analysis_id` để lưu chi tiết vào bảng `yara_matches`

### 6.3. Lưu Vào Bảng `yara_matches`

**File**: `backend/app/services/analysis_service.py` (dòng 72-99)

```python
# 6.3.1. Insert từng YARA match vào bảng yara_matches
yara_matches = analysis_data.get('yara_matches', [])
if yara_matches and analysis_id:
    match_count = 0
    for match in yara_matches:
        if isinstance(match, dict):
            match_sql = """
                INSERT INTO yara_matches (
                    analysis_id, rule_name, tags, description, 
                    author, reference, matched_strings
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            # 6.3.2. Extract thông tin từ match
            rule_name = match.get('rule', match.get('rule_name', ''))
            tags = ', '.join(match.get('tags', [])) if isinstance(match.get('tags'), list) else match.get('tags', '')
            description = match.get('description', match.get('meta', {}).get('description', ''))
            author = match.get('author', match.get('meta', {}).get('author', ''))
            reference = match.get('reference', match.get('meta', {}).get('reference', ''))
            matched_strings = json.dumps(match.get('matched_strings', [])) if match.get('matched_strings') else None
            
            # 6.3.3. Insert vào database
            await cursor.execute(match_sql, (
                analysis_id,
                rule_name,
                tags,
                description,
                author,
                reference,
                matched_strings  # JSON string
            ))
            match_count += 1
    
    logger.debug(f"Inserted {match_count} YARA matches for analysis {analysis_id}")
```

**Giải thích**:
- Lưu từng YARA match vào bảng `yara_matches`
- Mỗi match có: `rule_name`, `tags`, `description`, `author`, `reference`, `matched_strings`
- `matched_strings` được lưu dưới dạng JSON string
- Foreign key `analysis_id` liên kết với bảng `analyses`

**Ví dụ dữ liệu trong database**:

**Bảng `analyses`**:
```sql
id: 123
filename: "malware.exe"
yara_matches: '[{"rule_name": "DebuggerException__SetConsoleCtrl", ...}]'  -- JSON
```

**Bảng `yara_matches`**:
```sql
id: 1
analysis_id: 123
rule_name: "DebuggerException__SetConsoleCtrl"
tags: "AntiDebug, DebuggerException"
description: "Detects debugger evasion"
author: "Security Team"
reference: "https://example.com"
matched_strings: '[{"identifier": "$s1", "offset": 1024, ...}]'  -- JSON
```

---

## Trả Về Kết Quả

### 7.1. Tạo Response Object

**File**: `backend/app/api/v1/routes/scan.py` (dòng 50-61)

```python
# 7.1.1. Tạo ScanResult từ analysis_data
result = ScanResult(
    filename=file.filename,
    sha256=analysis_data.get("sha256"),
    md5=analysis_data.get("md5"),
    yara_matches=analysis_data.get("yara_matches", []),  # List of matches
    pe_info=analysis_data.get("pe_info"),
    suspicious_strings=analysis_data.get("suspicious_strings", []),  # Từ Static Analyzer, KHÔNG từ YARA
    capabilities=analysis_data.get("capabilities", []),
    malware_detected=analysis_data.get("malware_detected", False),
    analysis_time=analysis_data.get("analysis_time", 0.0),
    results=analysis_data.get("results", [])  # Chứa YARA results
)

return result  # FastAPI tự động serialize thành JSON
```

**Giải thích**:
- Tạo `ScanResult` object từ `analysis_data`
- `yara_matches` là list các matches chi tiết
- `results` chứa YARA results với type="yara"
- **Lưu ý**: `suspicious_strings` KHÔNG phải từ YARA, mà từ **Static Analyzer**

### 7.2. Phân Biệt: YARA Matched Strings vs Suspicious Strings

**YARA Matched Strings** (từ YARA scan):
- **Nguồn**: Các strings đã khớp với YARA rules
- **Vị trí**: Trong `yara_matches[].matched_strings[]`
- **Ví dụ**:
  ```json
  {
    "rule_name": "DebuggerException__SetConsoleCtrl",
    "matched_strings": [
      {
        "identifier": "$s1",
        "offset": 1024,
        "data": "4d5a9000",
        "data_preview": "MZ..."
      }
    ]
  }
  ```

**Suspicious Strings** (từ Static Analyzer):
- **Nguồn**: Static Analyzer extract từ file binary
- **Vị trí**: Trong `suspicious_strings[]` (top-level)
- **Ví dụ**:
  ```json
  {
    "suspicious_strings": [
      "http://192.168.1.100:8080/command",
      "CreateRemoteThread",
      "registry_startup_demo"
    ]
  }
  ```

**Sự khác biệt**:
- **YARA matched strings**: Chỉ các strings đã khớp với YARA rules (có rule name, offset, data)
- **Suspicious strings**: Tất cả strings đáng ngờ trong file (URLs, IPs, suspicious keywords, high entropy)

### 7.2. JSON Response

**Ví dụ response**:
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
      "author": "Security Team",
      "reference": "https://example.com",
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
  "malware_detected": true,
  "analysis_time": 2.5,
  "results": [
    {
      "type": "yara",
      "file": "uploads/malware.exe",
      "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, ...",
      "rule_count": 15,
      "detailed_matches": [...],
      "infoUrl": "https://bazaar.abuse.ch/sample/80b4182a.../"
    }
  ]
}
```

**Giải thích**:
- `yara_matches`: Chi tiết từng match (để hiển thị)
- `results`: Kết quả YARA với type="yara" (để hiển thị tổng hợp)
- `malware_detected`: `true` nếu có YARA match
- `infoUrl`: Link tham khảo từ bazaar.abuse.ch
- **`suspicious_strings`**: KHÔNG phải từ YARA, mà từ **Static Analyzer** (extract từ file binary)

---

## Ví Dụ Thực Tế

### Ví Dụ 1: File Có YARA Matches

**File**: `malware.exe`

**Quy trình**:

1. **Load rules** (khi start app):
   ```
   [YARA] Loading rules from: /app/yara_rules/rules/index.yar
   [OK] YARA rules loaded: 12159 rules
   ```

2. **Scan file**:
   ```python
   yara_results = yara_service.scan_file("uploads/malware.exe")
   ```

3. **YARA engine quét**:
   - Đọc file `malware.exe`
   - So khớp với 12,159 rules
   - Tìm thấy 15 rules match

4. **Kết quả**:
   ```python
   [
       {
           "type": "yara",
           "rule_count": 15,
           "detailed_matches": [
               {
                   "rule_name": "DebuggerException__SetConsoleCtrl",
                   "tags": ["AntiDebug"],
                   "matched_strings": [...]
               },
               # ... 14 matches khác
           ]
       }
   ]
   ```

5. **Lưu database**:
   - Insert vào `analyses` với `yara_matches` JSON
   - Insert 15 records vào `yara_matches`

6. **Trả về response**:
   ```json
   {
     "malware_detected": true,
     "yara_matches": [...],
     "results": [{"type": "yara", "rule_count": 15, ...}]
   }
   ```

### Ví Dụ 2: File Không Có YARA Matches

**File**: `clean_file.exe`

**Quy trình**:

1. **Scan file**:
   ```python
   yara_results = yara_service.scan_file("uploads/clean_file.exe")
   ```

2. **YARA engine quét**:
   - Đọc file `clean_file.exe`
   - So khớp với 12,159 rules
   - Không có rule nào match

3. **Kết quả**:
   ```python
   []  # Rỗng
   ```

4. **Lưu database**:
   - Insert vào `analyses` với `yara_matches = []`

5. **Trả về response**:
   ```json
   {
     "malware_detected": false,
     "yara_matches": [],
     "results": []
   }
   ```

### Ví Dụ 3: YARA Rules Không Load

**Tình huống**: File rules không tồn tại hoặc bị hỏng

**Quy trình**:

1. **Load rules** (khi start app):
   ```
   [WARN] YARA rules file not found: /app/yara_rules/rules/index.yar
   ```

2. **Scan file**:
   ```python
   yara_results = yara_service.scan_file("uploads/malware.exe")
   # Kết quả: []
   ```

3. **Log**:
   ```
   [YARA] WARNING: YARA rules not loaded, skipping scan for uploads/malware.exe
   ```

4. **Trả về response**:
   ```json
   {
     "malware_detected": false,
     "yara_matches": [],
     "results": []
   }
   ```

---

## Lưu Ý: YARA KHÔNG Trả Về Suspicious Strings

### Phân Biệt: YARA Matched Strings vs Suspicious Strings

**YARA KHÔNG trả về suspicious strings**. YARA chỉ trả về **matched strings** (các strings đã khớp với YARA rules).

**Suspicious strings** được lấy từ **Static Analyzer**, không phải từ YARA scan.

### YARA Matched Strings (từ YARA scan)

**Nguồn**: Các strings đã khớp với YARA rules

**Vị trí trong response**:
```json
{
  "yara_matches": [
    {
      "rule_name": "DebuggerException__SetConsoleCtrl",
      "matched_strings": [
        {
          "identifier": "$s1",
          "offset": 1024,
          "data": "4d5a9000",
          "data_preview": "MZ..."
        }
      ]
    }
  ]
}
```

**Giải thích**:
- Chỉ các strings đã khớp với YARA rules
- Có thông tin: rule name, offset, data, identifier
- Nằm trong `yara_matches[].matched_strings[]`

### Suspicious Strings (từ Static Analyzer)

**Nguồn**: Static Analyzer extract từ file binary

**Vị trí trong response**:
```json
{
  "suspicious_strings": [
    "http://192.168.1.100:8080/command",
    "CreateRemoteThread",
    "registry_startup_demo",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  ]
}
```

**Giải thích**:
- Tất cả strings đáng ngờ trong file (URLs, IPs, suspicious keywords, high entropy)
- Được extract bởi Static Analyzer, không phải YARA
- Nằm trong `suspicious_strings[]` (top-level)

**File xử lý**: `backend/app/services/static_analyzer_impl.py`
- Method: `_extract_strings()` - Extract strings từ binary
- Method: `_is_suspicious_string()` - Kiểm tra string có đáng ngờ không

**Các Patterns Được Coi Là Đáng Ngờ**:
 ` (dòng 19-33)

```python
self.suspicious_patterns = [
    r'http[s]?://[^\s]+',                    # URLs
    r'ftp://[^\s]+',                         # FTP URLs
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
    r'[A-Z]:\\[^\\s]+',                      # Đường dẫn Windows
    r'\\\\[^\\s]+',                          # UNC paths
    r'HKEY_[A-Z_]+',                         # Registry keys
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # Địa chỉ IP
    r'[0-9a-fA-F]{32,}',                     # Hex strings dài (hashes)
    r'cmd\.exe|powershell|wscript|cscript',  # Thực thi lệnh
    r'CreateRemoteThread|VirtualAlloc|WriteProcessMemory',  # API calls
    r'base64|Base64',                        # Encoding
    r'password|pwd|passwd|secret|key',      # Thông tin xác thực
    r'\.dll|\.exe|\.sys|\.bat|\.ps1',        # File thực thi
]
```

**Các Keywords Đáng Ngờ**:

**File**: `backend/app/services/static_analyzer_impl.py` (dòng 36-45)

```python
self.suspicious_keywords = [
    'malware', 'trojan', 'virus', 'backdoor', 'keylogger',
    'ransomware', 'spyware', 'rootkit', 'botnet', 'exploit',
    'payload', 'shellcode', 'inject', 'hook', 'bypass',
    'disable', 'delete', 'kill', 'terminate', 'remove',
    'registry', 'startup', 'autostart', 'persistence',
    'crypto', 'encrypt', 'decrypt', 'ransom', 'bitcoin',
    'c2', 'command', 'control', 'server', 'connect',
    'download', 'upload', 'exfiltrate', 'steal', 'collect'
]
```

**Cách Kiểm Tra**:

**File**: `backend/app/services/static_analyzer_impl.py` (dòng 169-187)

```python
def _is_suspicious_string(self, s: str) -> bool:
    """Kiểm tra string có đáng ngờ không"""
    s_lower = s.lower()
    
    # 1. Kiểm tra patterns (regex)
    for pattern in self.suspicious_patterns:
        if re.search(pattern, s, re.IGNORECASE):
            return True
    
    # 2. Kiểm tra keywords
    for keyword in self.suspicious_keywords:
        if keyword in s_lower:
            return True
    
    # 3. Kiểm tra entropy cao (strings ngẫu nhiên)
    if len(s) >= 16 and self._has_high_entropy(s):
        return True
    
    return False
```

**Cách lấy trong AnalyzerService**:
```python
# File: backend/app/services/analyzer_service.py (dòng 179)
'suspicious_strings': static_analysis.get("strings", [])[:20]  # Limit 20
```

**Lưu ý**: `suspicious_strings` trong response là từ Static Analyzer, KHÔNG phải từ YARA scan.

---

## Tóm Tắt

### Quy Trình Tổng Quan

1. **Load Rules** (khi start app):
   - Đọc file `yara_rules/rules/index.yar`
   - Compile tất cả rules
   - Lưu vào memory

2. **Scan File**:
   - Gọi `yara_service.scan_file(filepath)`
   - YARA engine quét file với tất cả rules
   - Trả về list matches

3. **Xử Lý Kết Quả**:
   - Extract thông tin từ matches
   - Tạo detailed_matches
   - Thêm infoUrl

4. **Lưu Database**:
   - Lưu vào `analyses.yara_matches` (JSON)
   - Lưu chi tiết vào `yara_matches` table

5. **Trả Về Response**:
   - Tạo ScanResult object
   - Serialize thành JSON
   - Trả về cho frontend

### Vị Trí Các File

- **Thư viện**: `yara-python==4.5.4` (requirements.txt)
- **Rules**: `backend/yara_rules/rules/index.yar`
- **Service**: `backend/app/services/yara_service.py`
- **Config**: `backend/app/core/config.py`
- **Database**: `backend/app/core/database.py` (schema)
- **Analysis Service**: `backend/app/services/analysis_service.py` (lưu kết quả)

---

**Tài liệu này giải thích chi tiết cách hệ thống sử dụng YARA để kiểm tra file, từ load rules đến lưu kết quả và trả về response.**

