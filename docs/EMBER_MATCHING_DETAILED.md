# Giải Thích Chi Tiết: So Sánh Khớp EMBER Model

## Mục Lục
1. [Tổng Quan EMBER](#1-tổng-quan-ember)
2. [Bước 1: Kiểm Tra PE File](#2-bước-1-kiểm-tra-pe-file)
3. [Bước 2: Trích Xuất Features](#3-bước-2-trích-xuất-features)
4. [Bước 3: Dự Đoán với LightGBM Model](#4-bước-3-dự-đoán-với-lightgbm-model)
5. [Bước 4: So Sánh với Threshold](#5-bước-4-so-sánh-với-threshold)
6. [So Sánh với YARA và Suspicious Strings](#6-so-sánh-với-yara-và-suspicious-strings)

---

## 1. Tổng Quan EMBER

### 1.1. EMBER là gì?

**EMBER** (Endgame Malware BEnchmark for Research) là một mô hình machine learning được thiết kế để phát hiện malware từ **PE files** (Portable Executable - định dạng file thực thi Windows).

**Đặc điểm**:
- Sử dụng **LightGBM** (Gradient Boosting Machine)
- Trích xuất **2381 features** từ PE file
- Dự đoán score từ **0.0** (sạch) đến **1.0** (malware)
- Threshold: **0.8336** (1% False Positive Rate)

### 1.2. Quy Trình Tổng Quan

```
File Binary (bytes)
    ↓
Bước 1: Kiểm tra PE file (MZ header, PE signature)
    ↓
Bước 2: Trích xuất 2381 features từ PE file
    ↓
Bước 3: Dự đoán với LightGBM model → Score (0.0 - 1.0)
    ↓
Bước 4: So sánh score với threshold (0.8336)
    ↓
Kết quả: is_malware = (score > threshold)
```

---

## 2. Bước 1: Kiểm Tra PE File

### 2.1. Tại Sao Cần Kiểm Tra PE?

EMBER **CHỈ** phân tích PE files (`.exe`, `.dll`, `.sys`, `.scr`, `.drv`, `.ocx`, `.cpl`, `.efi`, `.com`, `.msi`, `.bin`).

**Lý do**: EMBER được train trên dataset chỉ chứa PE files, nên không thể phân tích các loại file khác (PDF, DOC, JPG, ...).

### 2.2. Quy Trình Kiểm Tra

```python
# File: backend/app/ml/ember_model.py
def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
    """Kiểm tra file có phải PE file không"""
    # 1. Kiểm tra file tồn tại
    if not file_path_obj.exists():
        return False, "File does not exist"
    
    # 2. Kiểm tra kích thước (PE file phải >= 64 bytes)
    file_size = file_path_obj.stat().st_size
    if file_size < 64:
        return False, "File too small (PE files must be at least 64 bytes)"
    
    # 3. Kiểm tra MZ header (bytes đầu tiên)
    with open(file_path, 'rb') as f:
        header = f.read(2)  # Đọc 2 bytes đầu
        if header == b'MZ':  # MZ = Mark Zbikowski (người tạo PE format)
            # 4. Kiểm tra PE signature (ở offset 0x3C)
            f.seek(0x3C)  # Offset đến PE header
            pe_offset_bytes = f.read(4)  # Đọc 4 bytes (little-endian)
            pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
            
            # 5. Kiểm tra offset hợp lệ
            if pe_offset < file_size and pe_offset > 0:
                f.seek(pe_offset)
                pe_signature = f.read(2)  # Đọc 2 bytes
                if pe_signature == b'PE':  # PE signature
                    return True, None  # ✅ Là PE file
                else:
                    return False, f"Invalid PE signature. Expected 'PE', got: {pe_signature.hex()}"
            return True, None  # Có MZ header nhưng không đọc được PE offset
        else:
            return False, f"Invalid PE header. Expected 'MZ', got: {header.hex()}"
```

### 2.3. Ví Dụ Cụ Thể

#### **Ví Dụ 1: File PE Hợp Lệ**

**File**: `malware.exe`

**Bytes đầu tiên**:
```
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
...
```

**Quá trình kiểm tra**:
1. Đọc 2 bytes đầu: `4D 5A` → `b'MZ'` ✅
2. Đọc offset ở 0x3C: `00 00 00 00` → `pe_offset = 0`
3. Kiểm tra: `pe_offset = 0` → Không hợp lệ, nhưng có MZ header → **PE file** ✅

**Kết quả**: `is_pe = True` → Tiếp tục phân tích

---

#### **Ví Dụ 2: File Không Phải PE**

**File**: `document.pdf`

**Bytes đầu tiên**:
```
25 50 44 46 2D 31 2E 34 ...  (PDF signature: "%PDF-1.4")
```

**Quá trình kiểm tra**:
1. Đọc 2 bytes đầu: `25 50` → `b'%P'` ❌ (không phải `b'MZ'`)

**Kết quả**: `is_pe = False, error_detail = "Invalid PE header. Expected 'MZ', got: 2550"`

**Response**:
```python
{
    "error": "File is not a valid PE file. EMBER only analyzes PE files.",
    "error_detail": "Invalid PE header. Expected 'MZ', got: 2550",
    "is_malware": False,
    "score": 0.0
}
```

---

#### **Ví Dụ 3: File Quá Nhỏ**

**File**: `tiny.exe` (chỉ 32 bytes)

**Quá trình kiểm tra**:
1. File size = 32 bytes < 64 bytes ❌

**Kết quả**: `is_pe = False, error_detail = "File too small (32 bytes). PE files must be at least 64 bytes"`

---

## 3. Bước 2: Trích Xuất Features

### 3.1. Tổng Quan

Sau khi xác nhận file là PE, EMBER trích xuất **2381 features** từ file binary.

**2381 features** được chia thành **8 nhóm**:

| Nhóm | Số lượng | Mô tả |
|------|----------|-------|
| **ByteHistogram** | 256 | Tần suất xuất hiện của mỗi byte (0-255) |
| **ByteEntropyHistogram** | 256 | Entropy của từng byte |
| **StringExtractor** | 1024 | Thống kê về strings (length, printable, entropy) |
| **GeneralFileInfo** | 10 | Thông tin chung (file size, entry point, etc.) |
| **HeaderFileInfo** | 92 | Thông tin PE header |
| **SectionInfo** | 1000 | Thống kê về sections (entropy, size, etc.) |
| **ImportsInfo** | 128 | Thống kê về imports (DLLs, functions) |
| **ExportsInfo** | 64 | Thống kê về exports |
| **DataDirectories** | 39 | Thống kê về data directories |
| **TỔNG CỘNG** | **2381** | |

### 3.2. Chi Tiết Từng Nhóm Features

#### **A. ByteHistogram (256 features)**

**Mục đích**: Đếm tần suất xuất hiện của mỗi byte (0-255) trong file.

**Cách tính**:
```python
# File: backend/ember/features.py
class ByteHistogram(FeatureType):
    def process_raw_features(self, raw_obj):
        """Đếm tần suất mỗi byte"""
        bytez = raw_obj  # File binary (bytes)
        histogram = [0] * 256  # 256 features
        
        for byte in bytez:
            histogram[byte] += 1  # Tăng count cho byte đó
        
        # Normalize (chia cho tổng số bytes)
        total_bytes = len(bytez)
        if total_bytes > 0:
            histogram = [count / total_bytes for count in histogram]
        
        return histogram  # 256 giá trị (0.0 - 1.0)
```

**Ví dụ cụ thể**:

**File binary**: 
```
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
```

**Tính histogram**:
- Byte `0x4D` (77): Xuất hiện 1 lần → `histogram[77] = 1/16 = 0.0625`
- Byte `0x5A` (90): Xuất hiện 1 lần → `histogram[90] = 1/16 = 0.0625`
- Byte `0x00` (0): Xuất hiện 8 lần → `histogram[0] = 8/16 = 0.5`
- Byte `0xFF` (255): Xuất hiện 2 lần → `histogram[255] = 2/16 = 0.125`
- Các byte khác: `histogram[i] = 0.0`

**Kết quả**: 256 giá trị (mỗi giá trị là tần suất của một byte)

**Ý nghĩa**: 
- File có nhiều byte `0x00` → Có thể là file được padding
- File có phân bố đều → Có thể là encrypted/packed
- File có pattern đặc trưng → Có thể nhận diện loại malware

---

#### **B. ByteEntropyHistogram (256 features)**

**Mục đích**: Tính entropy của từng byte trong file (đo độ ngẫu nhiên).

**Cách tính**:
```python
# File: backend/ember/features.py
class ByteEntropyHistogram(FeatureType):
    def process_raw_features(self, raw_obj):
        """Tính entropy của từng byte"""
        bytez = raw_obj
        entropy_histogram = [0.0] * 256
        
        # Chia file thành các cửa sổ (windows) và tính entropy
        window_size = 256  # Kích thước cửa sổ
        for i in range(0, len(bytez) - window_size + 1, window_size):
            window = bytez[i:i+window_size]
            
            # Tính entropy của cửa sổ này
            entropy = calculate_shannon_entropy(window)
            
            # Lấy byte đầu tiên của cửa sổ
            first_byte = window[0]
            entropy_histogram[first_byte] += entropy
        
        # Normalize
        return entropy_histogram  # 256 giá trị
```

**Ví dụ cụ thể**:

**File binary**: 
```
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
```

**Tính entropy**:
- Cửa sổ `4D 5A 90 00 ...`: Entropy ≈ 2.5 (có pattern)
- Cửa sổ `FF FF 00 00 ...`: Entropy ≈ 1.0 (lặp lại nhiều)

**Kết quả**: 256 giá trị (entropy cho mỗi byte)

**Ý nghĩa**:
- Entropy cao → File có thể được encrypted/packed
- Entropy thấp → File có pattern rõ ràng (có thể là code thông thường)

---

#### **C. StringExtractor (1024 features)**

**Mục đích**: Thống kê về strings trong file (ASCII và Unicode).

**Cách tính**:
```python
# File: backend/ember/features.py
class StringExtractor(FeatureType):
    def process_raw_features(self, raw_obj):
        """Trích xuất thống kê về strings"""
        bytez = raw_obj
        features = []
        
        # Trích xuất ASCII strings
        ascii_strings = extract_ascii_strings(bytez)
        # Trích xuất Unicode strings
        unicode_strings = extract_unicode_strings(bytez)
        
        # Thống kê về độ dài strings
        # - Histogram độ dài (100 bins)
        # - Số lượng strings
        # - Entropy của strings
        # - Tỷ lệ printable characters
        # ... (tổng cộng 1024 features)
        
        return features  # 1024 giá trị
```

**Ví dụ cụ thể**:

**File binary chứa strings**:
```
... 68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73 2E 63 6F 6D ...
... 63 6D 64 2E 65 78 65 ...
```

**Thống kê**:
- Số lượng ASCII strings: 2
- Độ dài trung bình: 15 ký tự
- Entropy trung bình: 3.2
- Tỷ lệ printable: 0.95
- ... (1024 features khác)

**Kết quả**: 1024 giá trị

**Ý nghĩa**:
- Nhiều strings dài → Có thể chứa URLs, commands
- Entropy cao → Strings có thể được encoded
- Tỷ lệ printable thấp → Có thể là binary data

---

#### **D. GeneralFileInfo (10 features)**

**Mục đích**: Thông tin chung về file.

**Các features**:
1. File size (bytes)
2. Virtual size (memory size)
3. Entry point (địa chỉ bắt đầu thực thi)
4. Image base (base address)
5. Number of sections
6. Timestamp (compile time)
7. Machine type (x86/x64)
8. Characteristics (flags)
9. Subsystem (console/GUI)
10. DLL characteristics

**Ví dụ cụ thể**:

**File**: `malware.exe`

**Features**:
```python
[
    245760,      # File size: 245,760 bytes
    262144,      # Virtual size: 262,144 bytes
    4096,        # Entry point: 0x1000
    4194304,     # Image base: 0x400000
    7,           # Number of sections: 7
    1766198511,  # Timestamp: Unix timestamp
    34404,       # Machine: x64 (0x8664)
    0x2022,      # Characteristics: EXECUTABLE_IMAGE, ...
    2,           # Subsystem: Windows GUI
    0x8140       # DLL characteristics: ...
]
```

**Kết quả**: 10 giá trị

**Ý nghĩa**:
- Entry point bất thường → Có thể được pack/obfuscate
- Timestamp cũ → Có thể là file cũ hoặc fake timestamp
- Machine type → x86 hay x64

---

#### **E. HeaderFileInfo (92 features)**

**Mục đích**: Thông tin chi tiết về PE header.

**Các features**:
- COFF header fields (20 features)
- Optional header fields (72 features)
  - Magic number
  - Major/minor linker version
  - Size of code/data
  - Base of code/data
  - Image base
  - Section alignment
  - File alignment
  - Major/minor OS version
  - Major/minor image version
  - Major/minor subsystem version
  - Size of stack/heap reserve/commit
  - Loader flags
  - Number of RVA and sizes
  - ... (nhiều fields khác)

**Ví dụ cụ thể**:

**PE Header**:
```
PE Header:
  Machine: 0x8664 (x64)
  NumberOfSections: 7
  TimeDateStamp: 0x693A5F0F
  PointerToSymbolTable: 0
  NumberOfSymbols: 0
  SizeOfOptionalHeader: 240
  Characteristics: 0x2022
```

**Kết quả**: 92 giá trị

**Ý nghĩa**:
- Header fields bất thường → Có thể bị modify
- Version numbers → Có thể fake
- Alignment values → Có thể được pack

---

#### **F. SectionInfo (1000 features)**

**Mục đích**: Thống kê về các sections trong PE file.

**Các features** (cho mỗi section, tối đa 96 sections):
- Section name (hash)
- Virtual size
- Virtual address
- Raw size
- Raw address
- Entropy
- Characteristics
- ... (≈10 features/section)

**Ví dụ cụ thể**:

**File có 7 sections**:
```
Section 1: .text
  Virtual size: 184752
  Raw size: 184832
  Entropy: 6.48
  Characteristics: CODE, EXECUTE, READ

Section 2: .rdata
  Virtual size: 79578
  Raw size: 79872
  Entropy: 5.75
  Characteristics: INITIALIZED_DATA, READ

Section 3: .data
  Virtual size: 20656
  Raw size: 3584
  Entropy: 1.83
  Characteristics: INITIALIZED_DATA, READ, WRITE

... (4 sections khác)
```

**Kết quả**: 1000 giá trị (≈10 features × 96 sections, padding với 0 nếu < 96 sections)

**Ý nghĩa**:
- Entropy cao (> 7.0) → Section có thể được pack/encrypt
- Raw size << Virtual size → Có thể được compress
- Section name bất thường → Có thể được obfuscate

---

#### **G. ImportsInfo (128 features)**

**Mục đích**: Thống kê về imports (các DLL và hàm được import).

**Các features**:
- Số lượng DLLs được import
- Số lượng functions được import
- Histogram của DLL names (hash)
- Histogram của function names (hash)
- ... (128 features)

**Ví dụ cụ thể**:

**File imports**:
```
KERNEL32.dll:
  - CreateFileW
  - WriteFile
  - ReadFile
  - DeleteFileW
  - ...

USER32.dll:
  - CreateWindowExW
  - ShowWindow
  - ...

WS2_32.dll:
  - socket
  - connect
  - send
  - ...
```

**Thống kê**:
- Số lượng DLLs: 3
- Số lượng functions: 50
- DLL hash histogram: [hash1, hash2, hash3, ...]
- Function hash histogram: [hash1, hash2, ..., hash50, ...]

**Kết quả**: 128 giá trị

**Ý nghĩa**:
- Nhiều network DLLs (WS2_32, WININET) → Có thể kết nối mạng
- Nhiều dangerous APIs (CreateRemoteThread, VirtualAlloc) → Đáng ngờ
- Ít imports → Có thể được pack hoặc tự implement

---

#### **H. ExportsInfo (64 features)**

**Mục đích**: Thống kê về exports (các hàm được export, thường cho DLLs).

**Các features**:
- Số lượng exports
- Export names histogram (hash)
- Export ordinals
- ... (64 features)

**Ví dụ cụ thể**:

**File exports** (DLL):
```
Export 1: DllMain (ordinal 1)
Export 2: Initialize (ordinal 2)
Export 3: ProcessData (ordinal 3)
```

**Thống kê**:
- Số lượng exports: 3
- Export names histogram: [hash1, hash2, hash3, ...]

**Kết quả**: 64 giá trị

**Ý nghĩa**:
- Nhiều exports → Có thể là DLL hợp pháp
- Ít exports → Có thể là malware DLL
- Export names đáng ngờ → Có thể là malware

---

#### **I. DataDirectories (39 features)**

**Mục đích**: Thống kê về data directories trong PE file.

**Các features** (cho mỗi data directory):
- RVA (Relative Virtual Address)
- Size
- ... (≈3 features/directory × 13 directories = 39 features)

**Ví dụ cụ thể**:

**Data Directories**:
```
Import Table: RVA=0x2000, Size=0x500
Export Table: RVA=0x0000, Size=0x0000
Resource Table: RVA=0x3000, Size=0x1000
...
```

**Kết quả**: 39 giá trị

**Ý nghĩa**:
- Import table lớn → Nhiều dependencies
- Export table rỗng → Không phải DLL
- Resource table lớn → Có thể chứa embedded data

---

### 3.3. Quy Trình Trích Xuất Features

```python
# File: backend/app/ml/features.py
def feature_vector(self, bytez: bytes) -> np.ndarray:
    """Trích xuất 2381 features từ file PE"""
    # Sử dụng PEFeatureExtractor từ ember library
    features = self._extractor.feature_vector(bytez)
    # Trả về numpy array với 2381 features
    return features
```

**Ví dụ cụ thể**:

**Input**: File `malware.exe` (245,760 bytes)

**Quá trình**:
1. Đọc file binary: `bytez = open(filepath, 'rb').read()`
2. Trích xuất features:
   - ByteHistogram: 256 features
   - ByteEntropyHistogram: 256 features
   - StringExtractor: 1024 features
   - GeneralFileInfo: 10 features
   - HeaderFileInfo: 92 features
   - SectionInfo: 1000 features
   - ImportsInfo: 128 features
   - ExportsInfo: 64 features
   - DataDirectories: 39 features
3. **Tổng cộng**: 256 + 256 + 1024 + 10 + 92 + 1000 + 128 + 64 + 39 = **2381 features**

**Kết quả**: 
```python
features = np.array([
    0.0625, 0.0625, 0.5, ...,  # ByteHistogram (256)
    2.5, 1.0, ...,              # ByteEntropyHistogram (256)
    2, 15, 3.2, ...,            # StringExtractor (1024)
    245760, 262144, 4096, ...,  # GeneralFileInfo (10)
    ...,                        # HeaderFileInfo (92)
    ...,                        # SectionInfo (1000)
    ...,                        # ImportsInfo (128)
    ...,                        # ExportsInfo (64)
    ...                         # DataDirectories (39)
], dtype=np.float32)
# Shape: (2381,)
```

---

## 4. Bước 3: Dự Đoán với LightGBM Model

### 4.1. LightGBM Model

**LightGBM** (Light Gradient Boosting Machine) là một thuật toán machine learning sử dụng **Gradient Boosting**.

**Đặc điểm**:
- Model đã được train trên **800,000 PE files** (400,000 malware + 400,000 benign)
- Sử dụng **1000 cây quyết định** (decision trees)
- Model file: `ember_model_2018.txt` (~50-100MB)

### 4.2. Quy Trình Dự Đoán

```python
# File: backend/app/ml/ember_model.py
def predict(self, file_path: str) -> Dict[str, Any]:
    # 1. Đọc file binary
    with open(file_path, "rb") as f:
        bytez = f.read()
    
    # 2. Trích xuất features (2381 features)
    features = self.extractor.feature_vector(bytez)
    # features.shape = (2381,)
    
    # 3. Dự đoán với LightGBM model
    score = self.model.predict([features])[0]
    # score là một số float từ 0.0 đến 1.0
    
    return {
        "score": float(score),
        "is_malware": score > self.threshold,
        "threshold": self.threshold
    }
```

### 4.3. LightGBM Prediction Process

**LightGBM làm gì bên trong**:

1. **Input**: Feature vector (2381 features)
2. **Với mỗi cây quyết định** (1000 cây):
   - Đi từ root node xuống leaf node
   - Tại mỗi node, kiểm tra điều kiện (ví dụ: `feature[0] < 0.5`)
   - Đi theo nhánh True hoặc False
   - Đến leaf node → Lấy giá trị prediction
3. **Tổng hợp**: Cộng tất cả predictions từ 1000 cây
4. **Output**: Score (0.0 - 1.0)

**Ví dụ cụ thể**:

**Feature vector**:
```python
features = [
    0.0625,  # ByteHistogram[77] (byte 0x4D)
    0.0625,  # ByteHistogram[90] (byte 0x5A)
    0.5,     # ByteHistogram[0] (byte 0x00)
    ...      # (2381 features)
]
```

**LightGBM prediction**:

**Cây 1**:
```
Root: feature[0] < 0.1? → True
  Node: feature[1] < 0.1? → True
    Leaf: +0.05
```

**Cây 2**:
```
Root: feature[2] > 0.4? → True
  Node: feature[100] < 0.2? → False
    Leaf: +0.08
```

**... (998 cây khác)**

**Tổng hợp**:
```python
score = 0.05 + 0.08 + ... (từ 1000 cây)
score = 0.9234  # Ví dụ
```

**Kết quả**: `score = 0.9234`

---

### 4.4. Ví Dụ Cụ Thể

#### **Ví Dụ 1: File Malware**

**File**: `trojan.exe`

**Features**:
- ByteHistogram: Nhiều byte `0x00` (padding) → `histogram[0] = 0.3`
- ByteEntropyHistogram: Entropy cao ở một số sections → `entropy[100] = 7.5`
- StringExtractor: Nhiều strings đáng ngờ → `suspicious_strings_count = 50`
- GeneralFileInfo: Entry point bất thường → `entry_point = 0x5000`
- SectionInfo: Entropy cao ở section `.text` → `section_entropy[0] = 7.2`
- ImportsInfo: Nhiều dangerous APIs → `dangerous_apis_count = 20`

**LightGBM prediction**:
- Cây 1: `+0.05` (vì `histogram[0] > 0.2`)
- Cây 2: `+0.08` (vì `entropy[100] > 7.0`)
- Cây 3: `+0.10` (vì `suspicious_strings_count > 30`)
- ... (997 cây khác)
- **Tổng**: `score = 0.9234`

**Kết quả**: `score = 0.9234` → **MALWARE** ✅

---

#### **Ví Dụ 2: File Sạch**

**File**: `notepad.exe` (Windows Notepad)

**Features**:
- ByteHistogram: Phân bố bình thường → `histogram[0] = 0.05`
- ByteEntropyHistogram: Entropy thấp → `entropy[100] = 4.0`
- StringExtractor: Ít strings đáng ngờ → `suspicious_strings_count = 2`
- GeneralFileInfo: Entry point bình thường → `entry_point = 0x1000`
- SectionInfo: Entropy thấp → `section_entropy[0] = 5.0`
- ImportsInfo: Chỉ có standard APIs → `dangerous_apis_count = 0`

**LightGBM prediction**:
- Cây 1: `-0.02` (vì `histogram[0] < 0.1`)
- Cây 2: `-0.03` (vì `entropy[100] < 5.0`)
- Cây 3: `-0.01` (vì `suspicious_strings_count < 10`)
- ... (997 cây khác)
- **Tổng**: `score = 0.1234`

**Kết quả**: `score = 0.1234` → **SẠCH** ✅

---

## 5. Bước 4: So Sánh với Threshold

### 5.1. Threshold là gì?

**Threshold** = **0.8336** là ngưỡng được chọn để đạt **1% False Positive Rate** (FPR).

**Giải thích**:
- **False Positive Rate (FPR)**: Tỷ lệ file sạch bị nhận nhầm là malware
- **1% FPR**: Trong 100 file sạch, chỉ có 1 file bị nhận nhầm
- **Threshold 0.8336**: Nếu score > 0.8336 → Malware, ngược lại → Sạch

### 5.2. Quy Trình So Sánh

```python
# File: backend/app/ml/ember_model.py
score = 0.9234  # Từ LightGBM prediction
threshold = 0.8336

# So sánh
is_malware = score > threshold
# is_malware = 0.9234 > 0.8336 = True ✅
```

### 5.3. Ví Dụ Cụ Thể

#### **Ví Dụ 1: Score > Threshold**

**File**: `trojan.exe`

**Score**: `0.9234`
**Threshold**: `0.8336`

**So sánh**: `0.9234 > 0.8336` → **True** ✅

**Kết quả**:
```python
{
    "score": 0.9234,
    "is_malware": True,  # ✅ MALWARE
    "threshold": 0.8336
}
```

**Response trong API**:
```json
{
    "type": "model",
    "subtype": "ember",
    "message": "[MALWARE] EMBER detection (Score: 0.9234)",
    "score": 0.9234,
    "threshold": 0.8336
}
```

---

#### **Ví Dụ 2: Score < Threshold**

**File**: `notepad.exe`

**Score**: `0.1234`
**Threshold**: `0.8336`

**So sánh**: `0.1234 > 0.8336` → **False** ❌

**Kết quả**:
```python
{
    "score": 0.1234,
    "is_malware": False,  # ✅ SẠCH
    "threshold": 0.8336
}
```

**Response trong API**:
```json
{
    "type": "model",
    "subtype": "ember",
    "message": "[CLEAN] EMBER analysis (Score: 0.1234, Threshold: 0.8336)",
    "score": 0.1234,
    "threshold": 0.8336
}
```

---

#### **Ví Dụ 3: Score Gần Threshold**

**File**: `suspicious.exe`

**Score**: `0.8335`
**Threshold**: `0.8336`

**So sánh**: `0.8335 > 0.8336` → **False** ❌ (chỉ thiếu 0.0001!)

**Kết quả**:
```python
{
    "score": 0.8335,
    "is_malware": False,  # ❌ SẠCH (nhưng rất gần threshold)
    "threshold": 0.8336
}
```

**Lưu ý**: Score gần threshold có thể là **gray area** - cần phân tích thêm.

---

### 5.4. Tóm Tắt So Sánh Threshold

```
Score từ LightGBM (0.0 - 1.0)
    ↓
So sánh với threshold (0.8336)
    ↓
Nếu score > 0.8336:
    → is_malware = True  ✅ MALWARE
    → Message: "[MALWARE] EMBER detection (Score: X.XXXX)"
    ↓
Nếu score <= 0.8336:
    → is_malware = False  ✅ SẠCH
    → Message: "[CLEAN] EMBER analysis (Score: X.XXXX, Threshold: 0.8336)"
    ↓
Kết quả: EMBER result
```

---

## 6. So Sánh với YARA và Suspicious Strings

### 6.1. Bảng So Sánh

| Tiêu chí | Suspicious Strings | YARA Rules | EMBER Model |
|----------|-------------------|------------|-------------|
| **Mục đích** | Tìm strings đáng ngờ | So khớp với patterns | Dự đoán malware bằng ML |
| **Đọc file** | `open(filepath, 'rb')` | YARA engine tự đọc | `open(filepath, 'rb')` |
| **Chuyển đổi** | ❌ Không | ❌ Không | ❌ Không |
| **Yêu cầu** | Bất kỳ file nào | Bất kỳ file nào | **CHỈ PE files** |
| **So sánh** | Regex, keywords, entropy | Strings, hex, regex, condition | **2381 features → LightGBM** |
| **Kết quả** | Danh sách strings đáng ngờ | Danh sách rules đã match | **Score (0.0-1.0) + is_malware** |
| **Độ chính xác** | Thấp (nhiều false positive) | Cao (rules được viết cẩn thận) | **Cao (ML model được train)** |
| **Tốc độ** | Nhanh | Chậm (nhiều rules) | **Trung bình (phải extract features)** |
| **Cấu hình** | Hard-coded | Rules file (.yar) | **Model file (đã train sẵn)** |
| **Phát hiện mới** | ✅ Có (entropy) | ❌ Không (cần rule mới) | **✅ Có (ML học patterns)** |

### 6.2. Ưu và Nhược Điểm EMBER

#### **Ưu điểm**:
- ✅ **Phát hiện malware mới**: ML học patterns từ data, không cần signature
- ✅ **Độ chính xác cao**: Model được train trên 800,000 files
- ✅ **Tự động**: Không cần viết rules thủ công
- ✅ **Phân tích sâu**: 2381 features capture nhiều đặc điểm

#### **Nhược điểm**:
- ❌ **CHỈ hỗ trợ PE files**: Không thể phân tích PDF, DOC, JPG, ...
- ❌ **Chậm hơn YARA**: Phải extract 2381 features
- ❌ **Cần model file**: Model file lớn (~50-100MB)
- ❌ **False positives**: Vẫn có thể nhận nhầm (1% FPR)

### 6.3. Khi Nào Dùng EMBER?

**Dùng EMBER khi**:
- ✅ File là PE file (.exe, .dll, .sys, ...)
- ✅ Cần phát hiện malware mới (chưa có YARA rules)
- ✅ Cần độ chính xác cao
- ✅ Có thể chấp nhận tốc độ trung bình

**KHÔNG dùng EMBER khi**:
- ❌ File không phải PE (PDF, DOC, JPG, ...)
- ❌ Cần tốc độ nhanh (dùng YARA thay thế)
- ❌ File quá nhỏ (< 64 bytes)

**Dùng cả ba khi**:
- ✅ Cần phân tích toàn diện
- ✅ Kết hợp để giảm false positive
- ✅ Bổ sung cho nhau

---

## 7. Tóm Tắt Quy Trình EMBER

```
File Binary (bytes)
    ↓
Bước 1: Kiểm tra PE file
    ├─→ Kiểm tra MZ header (bytes đầu = 'MZ')?
    ├─→ Kiểm tra PE signature (offset 0x3C)?
    └─→ Kiểm tra file size (>= 64 bytes)?
    ↓
    Nếu KHÔNG phải PE → Trả về error
    ↓
    Nếu là PE → Tiếp tục
    ↓
Bước 2: Trích xuất 2381 features
    ├─→ ByteHistogram (256)
    ├─→ ByteEntropyHistogram (256)
    ├─→ StringExtractor (1024)
    ├─→ GeneralFileInfo (10)
    ├─→ HeaderFileInfo (92)
    ├─→ SectionInfo (1000)
    ├─→ ImportsInfo (128)
    ├─→ ExportsInfo (64)
    └─→ DataDirectories (39)
    ↓
Bước 3: Dự đoán với LightGBM model
    ├─→ Input: Feature vector (2381 features)
    ├─→ LightGBM: 1000 cây quyết định
    └─→ Output: Score (0.0 - 1.0)
    ↓
Bước 4: So sánh với threshold
    ├─→ score > 0.8336? → MALWARE ✅
    └─→ score <= 0.8336? → SẠCH ✅
    ↓
Kết quả: EMBER result
```

---

## 8. Code References

- **EMBER Model**: `backend/app/ml/ember_model.py`
  - `is_pe_file()`: Kiểm tra PE file
  - `predict()`: Dự đoán malware
  - `_load_model()`: Load LightGBM model

- **Feature Extractor**: `backend/app/ml/features.py`
  - `feature_vector()`: Trích xuất 2381 features
  - `_load_ember_extractor()`: Load PEFeatureExtractor

- **EMBER Library**: `backend/ember/features.py`
  - `PEFeatureExtractor`: Class chính trích xuất features
  - `ByteHistogram`, `ByteEntropyHistogram`, `StringExtractor`, ...

- **Model File**: `backend/models/ember_model_2018.txt`
  - LightGBM model đã được train sẵn

---

## 9. Tóm Tắt

### EMBER So Sánh Khớp Như Thế Nào?

1. **Kiểm tra PE file**: MZ header + PE signature
2. **Trích xuất 2381 features**: Từ 8 nhóm (histogram, entropy, strings, header, sections, imports, exports, data directories)
3. **Dự đoán với LightGBM**: 1000 cây quyết định → Score (0.0-1.0)
4. **So sánh với threshold**: `score > 0.8336` → Malware, ngược lại → Sạch

**Điểm khác biệt chính**:
- **YARA/Suspicious Strings**: So sánh trực tiếp với patterns/keywords
- **EMBER**: Trích xuất features → ML model dự đoán → So sánh với threshold

**Cả ba đều làm việc với binary data gốc, không cần chuyển đổi!**



