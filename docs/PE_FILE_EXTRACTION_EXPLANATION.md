# Giải Thích Chi Tiết: PE File và Cách Lấy Thông Tin PE

## 1. PE File Là Gì?

**PE (Portable Executable)** là định dạng file thực thi của Windows, được sử dụng cho:
- **.exe** - Executable files (chương trình thực thi)
- **.dll** - Dynamic Link Libraries (thư viện liên kết động)
- **.sys** - System drivers (driver hệ thống)
- **.scr** - Screen savers (bảo vệ màn hình)
- **.drv** - Device drivers (driver thiết bị)
- **.ocx** - OLE Control Extensions
- **.cpl** - Control Panel applets
- **.efi** - EFI executables
- **.com** - Command files
- **.msi** - Microsoft Installer packages

### 1.1. Cấu Trúc PE File

PE file có cấu trúc như sau:

```
┌─────────────────────────────────────┐
│  DOS Header (64 bytes)              │
│  - Magic: "MZ" (0x4D5A)              │ ← Bắt đầu từ đây
│  - PE Offset: Offset đến PE header  │
├─────────────────────────────────────┤
│  DOS Stub (optional)                 │
├─────────────────────────────────────┤
│  PE Signature: "PE\0\0" (4 bytes)   │ ← PE xuất hiện ở đây
├─────────────────────────────────────┤
│  COFF File Header                    │
│  - Machine (x86/x64)                 │
│  - Timestamp                         │
│  - Number of Sections                │
├─────────────────────────────────────┤
│  Optional Header                     │
├─────────────────────────────────────┤
│  Section Headers                     │
│  - .text (code)                      │
│  - .data (data)                      │
│  - .rdata (read-only data)           │
│  - .rsrc (resources)                 │
├─────────────────────────────────────┤
│  Sections Data                       │
│  - Code                              │
│  - Data                              │
│  - Resources                         │
└─────────────────────────────────────┘
```

## 2. PE Xuất Hiện Từ Đâu?

### 2.1. PE Xuất Hiện Từ File Binary

PE file là **file binary** (không phải text), được tạo ra bởi:
- **Compiler** (Visual Studio, GCC, etc.) khi compile C/C++/C# code
- **Linker** khi link các object files thành executable
- **Packers** (UPX, VMProtect) khi pack/compress file PE

### 2.2. PE Header Xuất Hiện Ở Đâu Trong File?

**Vị trí PE header trong file:**

1. **Byte 0-1**: DOS Magic "MZ" (0x4D5A)
2. **Byte 0x3C-0x3F**: Offset đến PE Signature (4 bytes, little-endian)
3. **Offset từ byte 0x3C**: PE Signature "PE\0\0" (4 bytes)
4. **Sau PE Signature**: COFF File Header, Optional Header, Section Headers

**Ví dụ:**
```
Offset 0x00: 4D 5A          ← "MZ" (DOS header)
Offset 0x3C: 80 00 00 00     ← PE offset = 0x80 (128 bytes)
Offset 0x80: 50 45 00 00     ← "PE\0\0" (PE signature)
Offset 0x84: 64 86          ← Machine = 0x8664 (x64)
...
```

## 3. Đoạn Code Nào Lấy Thông Tin PE?

### 3.1. Code Kiểm Tra File Có Phải PE Không

**File**: `backend/app/ml/ember_model.py`

```python
def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
    """Kiểm tra file có phải PE file không (kiểm tra MZ header)"""
    try:
        # 3.1.1. Kiểm tra file tồn tại
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return False, f"File does not exist: {file_path}"
        
        # 3.1.2. Kiểm tra kích thước file (tối thiểu 64 bytes)
        file_size = file_path_obj.stat().st_size
        if file_size < 64:
            return False, f"File too small ({file_size} bytes). PE files must be at least 64 bytes"
        
        # 3.1.3. Đọc 2 bytes đầu để kiểm tra MZ header
        with open(file_path, 'rb') as f:
            header = f.read(2)  # Đọc 2 bytes đầu
            if header == b'MZ':  # "MZ" = 0x4D5A
                # 3.1.4. Kiểm tra PE signature
                f.seek(0x3C)  # Di chuyển đến offset 0x3C
                pe_offset_bytes = f.read(4)  # Đọc 4 bytes (PE offset)
                if len(pe_offset_bytes) == 4:
                    # Chuyển đổi 4 bytes thành số (little-endian)
                    pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
                    
                    # Kiểm tra offset hợp lệ
                    if pe_offset < file_size and pe_offset > 0:
                        f.seek(pe_offset)  # Di chuyển đến PE signature
                        pe_signature = f.read(2)  # Đọc 2 bytes
                        if pe_signature == b'PE':  # "PE" = 0x5045
                            return True, None  # File PE hợp lệ
                        else:
                            return False, f"Invalid PE signature. Expected 'PE', got: {pe_signature.hex()}"
                # Nếu không đọc được PE offset, vẫn coi là PE nếu có MZ header
                return True, None
            else:
                header_hex = header.hex().upper() if len(header) == 2 else "N/A"
                return False, f"Invalid PE header. Expected 'MZ', got: {header_hex}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"
```

**Giải thích từng bước:**

1. **Kiểm tra file tồn tại**: Dùng `Path.exists()`
2. **Kiểm tra kích thước**: PE file phải >= 64 bytes (DOS header = 64 bytes)
3. **Đọc MZ header**: Đọc 2 bytes đầu, phải là `b'MZ'` (0x4D5A)
4. **Đọc PE offset**: Ở offset 0x3C, đọc 4 bytes (little-endian) để biết vị trí PE signature
5. **Kiểm tra PE signature**: Ở vị trí PE offset, đọc 2 bytes, phải là `b'PE'` (0x5045)

### 3.2. Code Phân Tích Thông Tin PE

**File**: `backend/app/services/static_analyzer_impl.py`

```python
def _analyze_pe_file(self, filepath: str, content: bytes) -> Optional[Dict[str, Any]]:
    """Phân tích cấu trúc file PE"""
    try:
        # 3.2.1. Sử dụng thư viện pefile để parse PE file
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        
        # 3.2.2. Tạo dictionary chứa thông tin PE
        pe_info = {
            "machine": pe.FILE_HEADER.Machine,           # 34404 (x64) hoặc 332 (x86)
            "timestamp": pe.FILE_HEADER.TimeDateStamp,    # Unix timestamp
            "sections": [],                               # Danh sách sections
            "imports": [],                                # Danh sách imports
            "exports": [],                                # Danh sách exports
            "suspicious_features": []                     # Các tính năng đáng ngờ
        }
        
        # 3.2.3. Phân tích sections (các phần của file PE)
        for section in pe.sections:
            try:
                section_data = {
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    # Ví dụ: ".text", ".data", ".rdata", ".rsrc"
                    "virtual_address": section.VirtualAddress,      # Địa chỉ ảo
                    "virtual_size": section.Misc_VirtualSize,        # Kích thước ảo
                    "raw_size": section.SizeOfRawData,              # Kích thước thực
                    "entropy": self._calculate_entropy(section.get_data())  # Entropy
                }
                pe_info["sections"].append(section_data)
                
                # 3.2.4. Kiểm tra entropy cao (có thể bị pack/obfuscate)
                if section_data["entropy"] > 7.0:
                    pe_info["suspicious_features"].append(
                        "High entropy section (possibly packed)"
                    )
            except:
                continue
        
        # 3.2.5. Phân tích imports (các hàm được import từ DLL)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    # Ví dụ: "KERNEL32.dll", "USER32.dll", "WS2_32.dll"
                    for imp in entry.imports:
                        if imp.name:
                            pe_info["imports"].append({
                                "dll": dll_name,
                                "function": imp.name.decode('utf-8', errors='ignore')
                                # Ví dụ: "CreateFileW", "VirtualAlloc", "socket"
                            })
        except:
            pass
        
        # 3.2.6. Phân tích exports (các hàm được export)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_info["exports"].append(
                            exp.name.decode('utf-8', errors='ignore')
                        )
        except:
            pass
        
        pe.close()  # Đóng PE object
        return pe_info
        
    except pefile.PEFormatError:
        # File không phải PE hoặc format không hợp lệ
        return None
    except Exception as e:
        print(f"[StaticAnalyzer] Error analyzing PE: {e}")
        return None
```

**Giải thích từng bước:**

1. **Sử dụng thư viện `pefile`**: Thư viện Python để parse PE file
2. **Đọc FILE_HEADER**: Lấy thông tin machine (x86/x64) và timestamp
3. **Phân tích sections**: Đọc từng section (.text, .data, .rdata, .rsrc) và tính entropy
4. **Phân tích imports**: Đọc danh sách DLL và hàm được import
5. **Phân tích exports**: Đọc danh sách hàm được export (nếu có)
6. **Kiểm tra suspicious features**: Phát hiện entropy cao (có thể bị pack)

## 4. Lấy Từ Đâu?

### 4.1. Lấy Từ File Binary

Thông tin PE được lấy trực tiếp từ **file binary** mà người dùng upload:

```
User uploads: encryption.exe
    ↓
Backend saves to: backend/uploads/encryption.exe
    ↓
StaticAnalyzer reads: backend/uploads/encryption.exe
    ↓
pefile.PE() parses binary structure
    ↓
Extract: machine, timestamp, sections, imports, exports
```

### 4.2. Lấy Từ Cấu Trúc PE Header

Thông tin được lấy từ các phần khác nhau của PE header:

| Thông Tin | Lấy Từ Đâu | Ví Dụ |
|-----------|------------|-------|
| **Machine** | `FILE_HEADER.Machine` | 34404 (x64), 332 (x86) |
| **Timestamp** | `FILE_HEADER.TimeDateStamp` | 1766198511 (Unix timestamp) |
| **Sections** | `pe.sections[]` | .text, .data, .rdata, .rsrc |
| **Imports** | `DIRECTORY_ENTRY_IMPORT` | KERNEL32.dll → CreateFileW |
| **Exports** | `DIRECTORY_ENTRY_EXPORT` | DllMain, ExportFunction |

## 5. Lấy Bằng Cách Nào?

### 5.1. Sử Dụng Thư Viện `pefile`

**Thư viện**: `pefile` (Python)

**Cài đặt**: `pip install pefile`

**Cách sử dụng**:

```python
import pefile

# Mở PE file
pe = pefile.PE("file.exe", fast_load=True)

# Đọc thông tin
machine = pe.FILE_HEADER.Machine
timestamp = pe.FILE_HEADER.TimeDateStamp

# Đọc sections
for section in pe.sections:
    name = section.Name.decode('utf-8')
    entropy = calculate_entropy(section.get_data())

# Đọc imports
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8')
    for imp in entry.imports:
        function = imp.name.decode('utf-8')

# Đóng file
pe.close()
```

### 5.2. Sử Dụng Thư Viện `lief` (Cho EMBER)

**Thư viện**: `lief` (C++ library, Python bindings)

**Cài đặt**: `pip install lief`

**Cách sử dụng** (trong EMBER feature extraction):

```python
import lief

# Parse PE file
binary = lief.parse("file.exe")

# Extract features
features = extract_features(binary)
# → 2381 features cho EMBER model
```

### 5.3. Đọc Binary Trực Tiếp (Manual)

**Cách đọc thủ công** (không dùng thư viện):

```python
with open("file.exe", 'rb') as f:
    # Đọc MZ header
    mz_header = f.read(2)  # "MZ"
    
    # Đọc PE offset
    f.seek(0x3C)
    pe_offset = int.from_bytes(f.read(4), 'little')
    
    # Đọc PE signature
    f.seek(pe_offset)
    pe_signature = f.read(2)  # "PE"
    
    # Đọc machine
    machine = int.from_bytes(f.read(2), 'little')
    
    # Đọc timestamp
    timestamp = int.from_bytes(f.read(4), 'little')
```

## 6. Luồng Xử Lý PE Trong Hệ Thống

### 6.1. Khi User Upload File

```
1. User uploads: encryption.exe
   ↓
2. Backend saves: backend/uploads/encryption.exe
   ↓
3. AnalyzerService.analyze_and_save()
   ↓
4. StaticAnalyzerService.analyze_file()
   ↓
5. StaticAnalyzer._analyze_pe_file()
   ↓
6. pefile.PE() parses file
   ↓
7. Extract: machine, timestamp, sections, imports, exports
   ↓
8. Return pe_info dictionary
   ↓
9. Save to database (JSON)
   ↓
10. Return to frontend
```

### 6.2. Code Thực Tế Trong Hệ Thống

**File**: `backend/app/services/analyzer_service.py`

```python
async def analyze_and_save(self, filepath: str, filename: str, scan_modules: List[str] = None):
    # 6.2.1. Phân tích file với Static Analyzer
    static_analysis = self.static_analyzer_service.analyze_file(filepath)
    
    # 6.2.2. Lấy thông tin PE (nếu là PE file)
    pe_info = static_analysis.get("pe_info")
    # → {
    #     "machine": 34404,
    #     "timestamp": 1766198511,
    #     "sections": [...],
    #     "imports": [...],
    #     "exports": [...],
    #     "suspicious_features": [...]
    # }
    
    # 6.2.3. Lưu vào database
    analysis_data = {
        'pe_info': pe_info,  # Lưu dưới dạng JSON
        ...
    }
    
    # 6.2.4. Trả về cho frontend
    return ScanResult(
        pe_info=pe_info,
        ...
    )
```

## 7. Ví Dụ Cụ Thể

### 7.1. File: `encryption.exe`

**Thông tin PE được extract:**

```json
{
  "machine": 34404,           // x64 architecture
  "timestamp": 1766198511,     // Unix timestamp
  "sections": [
    {
      "name": ".text",
      "virtual_address": 4096,
      "virtual_size": 184752,
      "raw_size": 184832,
      "entropy": 6.483896105726929
    },
    {
      "name": ".rdata",
      "virtual_address": 192512,
      "virtual_size": 79578,
      "raw_size": 79872,
      "entropy": 5.754672587814352
    },
    {
      "name": ".rsrc",
      "virtual_address": 315392,
      "virtual_size": 61324,
      "raw_size": 61440,
      "entropy": 7.350146920468335  // High entropy → possibly packed
    }
  ],
  "imports": [
    {
      "dll": "KERNEL32.dll",
      "function": "CreateFileW"
    },
    {
      "dll": "KERNEL32.dll",
      "function": "VirtualAlloc"
    },
    {
      "dll": "USER32.dll",
      "function": "MessageBoxW"
    }
  ],
  "exports": [],
  "suspicious_features": [
    "High entropy section (possibly packed)"
  ]
}
```

### 7.2. Cách Đọc Thông Tin Này

**Từ file binary `encryption.exe`:**

1. **Byte 0x00-0x01**: `4D 5A` → "MZ" header
2. **Byte 0x3C-0x3F**: `80 00 00 00` → PE offset = 0x80
3. **Byte 0x80-0x81**: `50 45` → "PE" signature
4. **Byte 0x84-0x85**: `64 86` → Machine = 0x8664 (x64)
5. **Byte 0x88-0x8B**: `EF 69 69 69` → Timestamp = 0x696969EF
6. **Sections**: Đọc từ Section Headers
7. **Imports**: Đọc từ Import Directory Table
8. **Exports**: Đọc từ Export Directory Table

## 8. Tóm Tắt

### 8.1. PE Là Gì?
- **PE (Portable Executable)** = Định dạng file thực thi Windows
- Bao gồm: .exe, .dll, .sys, .scr, .drv, .ocx, .cpl, .efi, .com, .msi

### 8.2. PE Xuất Hiện Từ Đâu?
- Từ **file binary** mà user upload
- Từ **cấu trúc PE header** trong file (MZ header → PE signature → COFF header → Sections)

### 8.3. Lấy Từ Đâu?
- Từ **file binary** trên disk: `backend/uploads/filename.exe`
- Từ **PE header structure**: FILE_HEADER, Optional Header, Section Headers, Import/Export Directories

### 8.4. Lấy Bằng Cách Nào?
- **Thư viện `pefile`**: Parse PE file và extract thông tin
- **Thư viện `lief`**: Extract features cho EMBER model
- **Đọc binary trực tiếp**: Đọc bytes và parse thủ công

### 8.5. Đoạn Code Nào?
- **Kiểm tra PE**: `backend/app/ml/ember_model.py` → `is_pe_file()`
- **Phân tích PE**: `backend/app/services/static_analyzer_impl.py` → `_analyze_pe_file()`
- **Sử dụng**: `backend/app/services/analyzer_service.py` → `analyze_and_save()`

---

**Tài Liệu Tham Khảo:**
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [pefile Documentation](https://github.com/erocarrera/pefile)
- [lief Documentation](https://lief-project.github.io/)

