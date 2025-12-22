# Giải Thích: Tại Sao Scan YARA Lại Có Thông Tin PE?

## 1. Câu Hỏi

**Tại sao khi scan bằng YARA lại có thông tin PE?**
- YARA scan chỉ dùng để phát hiện malware dựa trên patterns
- PE info là thông tin về cấu trúc file PE
- **Hai thứ này khác nhau, nhưng được combine trong kết quả**

## 2. Giải Thích Ngắn Gọn

**Khi bạn scan YARA, hệ thống làm 2 việc:**

1. **YARA Scan** → Phát hiện malware dựa trên patterns (YARA rules)
2. **Static Analyzer** → Extract thông tin PE (sections, imports, exports, entropy)

**Cả 2 được chạy song song và combine trong kết quả cuối cùng.**

## 3. Luồng Xử Lý Chi Tiết

### 3.1. Khi User Gọi API `/api/scan/yara`

**File**: `backend/app/api/v1/routes/scan.py` (dòng 72-109)

```python
@router.post("/yara", response_model=ScanResult)
async def scan_yara(file: UploadFile = File(...)):
    """
    API Quét YARA (Nhanh)
    - Chỉ sử dụng luật YARA để phát hiện malware
    """
    # 3.1.1. Lưu file upload
    filepath = settings.UPLOAD_FOLDER / file.filename
    with open(filepath, "wb") as f:
        f.write(await file.read())
    
    try:
        # 3.1.2. Gọi analyze_and_save() với scan_modules=["yara"]
        analysis_data = await analyzer_service.analyze_and_save(
            str(filepath), 
            file.filename, 
            scan_modules=["yara"]  # ← CHỈ chạy YARA scan
        )
        
        # 3.1.3. Trả về kết quả (bao gồm cả PE info)
        return ScanResult(
            filename=file.filename,
            sha256=analysis_data.get("sha256"),
            md5=analysis_data.get("md5"),
            yara_matches=analysis_data.get("yara_matches", []),  # ← Từ YARA scan
            pe_info=analysis_data.get("pe_info"),  # ← Từ Static Analyzer
            suspicious_strings=analysis_data.get("suspicious_strings", []),  # ← Từ Static Analyzer
            capabilities=analysis_data.get("capabilities", []),  # ← Từ Static Analyzer
            malware_detected=analysis_data.get("malware_detected", False),
            analysis_time=analysis_data.get("analysis_time", 0.0),
            results=analysis_data.get("results", [])  # ← Chứa YARA results
        )
```

**Giải thích:**
- `scan_modules=["yara"]` → Chỉ chạy YARA scan (không chạy Hash hay EMBER)
- **NHƯNG** `analyze_and_save()` vẫn gọi Static Analyzer để lấy PE info

### 3.2. Hàm `analyze_and_save()` Làm Gì?

**File**: `backend/app/services/analyzer_service.py` (dòng 126-203)

```python
async def analyze_and_save(self, filepath: str, filename: str, scan_modules: List[str] = None) -> Dict[str, Any]:
    """
    Phân tích file và lưu kết quả vào database
    """
    start_time = time.time()
    
    # 3.2.1. BƯỚC 1: Chạy các scan modules (YARA, Hash, EMBER)
    results = await self.analyze_single_file(filepath, scan_modules)
    # → Nếu scan_modules=["yara"]:
    #    - Chỉ chạy YARA scan
    #    - Không chạy Hash check
    #    - Không chạy EMBER
    # → results = [{"type": "yara", "matches": "...", ...}]
    
    # 3.2.2. BƯỚC 2: Chạy Static Analyzer (LUÔN chạy, bất kể scan_modules)
    static_analysis = self.analyze_with_static_analyzer(filepath)
    # → LUÔN chạy Static Analyzer để lấy:
    #    - pe_info (nếu file là PE)
    #    - suspicious_strings
    #    - capabilities
    #    - hashes (SHA256, MD5)
    
    elapsed = time.time() - start_time
    
    # 3.2.3. BƯỚC 3: Xác định malware_detected
    malware_detected = any(
        result.get("type") in ["hash", "yara", "model"] 
        for result in results
    )
    # → Nếu có YARA match → malware_detected = True
    
    # 3.2.4. BƯỚC 4: Extract YARA matches từ results
    yara_matches_for_db = []
    for result in results:
        if result.get("type") == "yara" and result.get("detailed_matches"):
            yara_matches_for_db.extend(result.get("detailed_matches", []))
    
    # 3.2.5. BƯỚC 5: Combine tất cả thông tin
    analysis_data = {
        'filename': filename,
        'sha256': sha256,
        'md5': md5,
        'file_size': file_size,
        'upload_time': datetime.now(),
        'analysis_time': elapsed,
        'malware_detected': malware_detected,  # ← Từ YARA scan
        'yara_matches': yara_matches_for_db,  # ← Từ YARA scan
        'pe_info': static_analysis.get("pe_info"),  # ← Từ Static Analyzer
        'suspicious_strings': static_analysis.get("strings", [])[:20],  # ← Từ Static Analyzer
        'capabilities': static_analysis.get("capabilities", []),  # ← Từ Static Analyzer
        'results': results  # ← Chứa YARA results
    }
    
    # 3.2.6. Lưu vào database
    analysis_id = await self.analysis_service.create(analysis_data)
    
    return analysis_data
```

**Điểm quan trọng:**
- **BƯỚC 1**: Chạy YARA scan (theo `scan_modules`)
- **BƯỚC 2**: **LUÔN chạy Static Analyzer** (bất kể `scan_modules`)
- **BƯỚC 5**: Combine cả 2 kết quả

### 3.3. Static Analyzer Làm Gì?

**File**: `backend/app/services/static_analyzer_impl.py` (dòng 47-89)

```python
def analyze_file(self, filepath: str) -> Dict[str, Any]:
    """
    Phân tích file và extract thông tin
    """
    result = {
        "hashes": self._calculate_hashes(filepath),  # SHA256, MD5
        "yara_matches": [],  # Sẽ được fill bởi YaraService (nếu cần)
        "pe_info": None,  # ← Thông tin PE
        "strings": [],  # ← Suspicious strings
        "capabilities": []  # ← Capabilities
    }
    
    # Extract strings
    result["strings"] = self._extract_strings(file_content)
    
    # Try to parse as PE file
    try:
        pe_info = self._analyze_pe_file(filepath, file_content)
        if pe_info:
            result["pe_info"] = pe_info  # ← Lấy thông tin PE
            result["capabilities"] = self._extract_capabilities(pe_info)
    except Exception as e:
        # Nếu không phải PE file → pe_info = None
        print(f"[StaticAnalyzer] Not a PE file or error parsing: {e}")
    
    return result
```

**Giải thích:**
- Static Analyzer **LUÔN chạy** khi gọi `analyze_and_save()`
- Nếu file là PE → Extract `pe_info` (sections, imports, exports, entropy)
- Nếu không phải PE → `pe_info = None`

## 4. Ví Dụ Cụ Thể: File `Annoying.exe`

### 4.1. Kết Quả Trả Về

```json
{
  "id": 318,
  "filename": "Annoying.exe",
  "malware_detected": 1,  // ← Từ YARA scan (có match)
  "yara_matches": [       // ← Từ YARA scan
    {
      "id": 598,
      "analysis_id": 318,
      "rule_name": "SEH_Save",
      ...
    },
    // ... 21 matches khác
  ],
  "pe_info": {            // ← Từ Static Analyzer (KHÔNG phải từ YARA)
    "exports": [],
    "imports": [],
    "machine": 332,       // x86 architecture
    ...
  },
  "results": [            // ← Chứa YARA results
    {
      "file": "/app/uploads/Annoying.exe",
      "type": "yara",
      ...
    }
  ]
}
```

### 4.2. Giải Thích Từng Phần

#### 4.2.1. `yara_matches` (22 matches)

**Nguồn**: Từ YARA scan (`YaraService.scan_file()`)

**Cách lấy:**
1. YARA scan file `Annoying.exe`
2. Tìm thấy 22 rules khớp
3. Extract thông tin chi tiết cho mỗi match:
   - `rule_name`: Tên rule (ví dụ: "SEH_Save")
   - `tags`: Tags của rule (ví dụ: "AntiDebug")
   - `description`: Mô tả rule
   - `author`: Tác giả rule
   - `reference`: Link tham khảo
   - `matched_strings`: Các strings đã khớp

**Code:**
```python
# File: backend/app/services/yara_service.py
yara_results = self.yara_service.scan_file(filepath)
# → Trả về list các matches với detailed_matches

# File: backend/app/services/analyzer_service.py (dòng 159-166)
yara_matches_for_db = []
for result in results:
    if result.get("type") == "yara" and result.get("detailed_matches"):
        yara_matches_for_db.extend(result.get("detailed_matches", []))
```

#### 4.2.2. `pe_info` (Thông Tin PE)

**Nguồn**: Từ Static Analyzer (`StaticAnalyzer._analyze_pe_file()`)

**Cách lấy:**
1. Static Analyzer kiểm tra file có phải PE không
2. Nếu là PE → Parse PE header bằng `pefile` library
3. Extract thông tin:
   - `machine`: 332 (x86) hoặc 34404 (x64)
   - `timestamp`: Unix timestamp
   - `sections`: Danh sách sections (.text, .data, .rdata, .rsrc)
   - `imports`: Danh sách DLL và functions được import
   - `exports`: Danh sách functions được export
   - `suspicious_features`: Các tính năng đáng ngờ (entropy cao, etc.)

**Code:**
```python
# File: backend/app/services/analyzer_service.py (dòng 141)
static_analysis = self.analyze_with_static_analyzer(filepath)
# → LUÔN chạy, bất kể scan_modules

# File: backend/app/services/analyzer_service.py (dòng 178)
'pe_info': static_analysis.get("pe_info"),  # ← Lấy từ Static Analyzer
```

## 5. Tại Sao Thiết Kế Như Vậy?

### 5.1. Lý Do

1. **YARA Scan** → Phát hiện malware nhanh dựa trên patterns
2. **PE Info** → Cung cấp thông tin chi tiết về file để phân tích sâu hơn
3. **Kết hợp cả 2** → Vừa phát hiện malware, vừa có thông tin chi tiết để phân tích

### 5.2. Lợi Ích

- **Phát hiện nhanh**: YARA scan nhanh, phát hiện malware ngay
- **Thông tin chi tiết**: PE info giúp hiểu rõ cấu trúc file
- **Phân tích sâu**: Có thể xem imports, exports, entropy để phân tích thêm
- **Lưu trữ đầy đủ**: Lưu cả YARA matches và PE info vào database

## 6. Sơ Đồ Luồng Xử Lý

```
User uploads: Annoying.exe
    ↓
API: /api/scan/yara
    ↓
analyzer_service.analyze_and_save(scan_modules=["yara"])
    ↓
┌─────────────────────────────────────────┐
│  BƯỚC 1: analyze_single_file()          │
│  - Chỉ chạy YARA scan                   │
│  - YaraService.scan_file()              │
│  → Tìm thấy 22 YARA matches             │
│  → results = [{"type": "yara", ...}]    │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  BƯỚC 2: analyze_with_static_analyzer() │
│  - LUÔN chạy (bất kể scan_modules)      │
│  - StaticAnalyzer.analyze_file()         │
│  → Parse PE file                         │
│  → Extract pe_info (machine, sections,  │
│     imports, exports, entropy)           │
│  → Extract suspicious_strings            │
│  → Extract capabilities                  │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  BƯỚC 3: Combine Results                │
│  - malware_detected = True (có YARA)    │
│  - yara_matches = [22 matches]          │
│  - pe_info = {machine: 332, ...}        │
│  - suspicious_strings = [...]           │
│  - capabilities = []                     │
└─────────────────────────────────────────┘
    ↓
Lưu vào database
    ↓
Trả về cho frontend
```

## 7. Phân Biệt: YARA Matches vs PE Info

### 7.1. YARA Matches

| Thuộc Tính | Giá Trị |
|------------|---------|
| **Nguồn** | YARA scan (`YaraService.scan_file()`) |
| **Mục đích** | Phát hiện malware dựa trên patterns |
| **Chạy khi nào** | Khi `scan_modules` chứa `"yara"` |
| **Kết quả** | List các rules khớp với file |
| **Ví dụ** | `{"rule_name": "SEH_Save", "tags": "AntiDebug", ...}` |

### 7.2. PE Info

| Thuộc Tính | Giá Trị |
|------------|---------|
| **Nguồn** | Static Analyzer (`StaticAnalyzer._analyze_pe_file()`) |
| **Mục đích** | Extract thông tin cấu trúc file PE |
| **Chạy khi nào** | **LUÔN chạy** (bất kể `scan_modules`) |
| **Kết quả** | Thông tin PE (machine, sections, imports, exports) |
| **Ví dụ** | `{"machine": 332, "sections": [...], "imports": [...]}` |

## 8. Tóm Tắt

### 8.1. Tại Sao Scan YARA Lại Có PE Info?

**Trả lời:**
- YARA scan và PE analysis là **2 module riêng biệt**
- Khi scan YARA, hệ thống **vẫn chạy Static Analyzer** để lấy PE info
- Cả 2 được **combine** trong kết quả cuối cùng

### 8.2. YARA Matches (22) Là Gì?

**Trả lời:**
- **22 YARA matches** = 22 rules YARA khớp với file `Annoying.exe`
- Mỗi match chứa:
  - `rule_name`: Tên rule
  - `tags`: Tags (ví dụ: "AntiDebug", "PECheck")
  - `description`: Mô tả
  - `matched_strings`: Các strings đã khớp

### 8.3. YARA Rule Matches Là Gì?

**Trả lời:**
- **YARA rule matches** = Các rules YARA đã khớp với file
- Được lấy từ `YaraService.scan_file()`
- Lưu trong `yara_matches[]` và `results[]`

### 8.4. Thông Tin PE Từ Đâu?

**Trả lời:**
- **Từ Static Analyzer**, không phải từ YARA
- Static Analyzer **LUÔN chạy** khi gọi `analyze_and_save()`
- Parse PE file bằng `pefile` library
- Extract: machine, timestamp, sections, imports, exports, entropy

---

**Kết Luận:**
- YARA scan → Phát hiện malware (22 matches)
- Static Analyzer → Extract PE info (machine: 332, sections, imports, exports)
- **Cả 2 được combine** trong kết quả cuối cùng
- **Không có mâu thuẫn** - đây là thiết kế của hệ thống để cung cấp thông tin đầy đủ

