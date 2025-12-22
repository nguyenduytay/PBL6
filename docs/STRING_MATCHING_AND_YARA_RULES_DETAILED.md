# Giải Thích Chi Tiết: So Sánh Khớp Tiêu Chí Đáng Nghi Ngờ và YARA Rules

## Mục Lục
1. [So Sánh Khớp Tiêu Chí Đáng Nghi Ngờ (Suspicious Strings)](#1-so-sánh-khớp-tiêu-chí-đáng-nghi-ngờ)
2. [So Sánh YARA Rules](#2-so-sánh-yara-rules)
3. [So Sánh Hai Phương Pháp](#3-so-sánh-hai-phương-pháp)

---

## 1. So Sánh Khớp Tiêu Chí Đáng Nghi Ngờ (Suspicious Strings)

### 1.1. Tổng Quan

**Mục đích**: Tìm các chuỗi ký tự đáng ngờ trong file binary để phát hiện dấu hiệu malware.

**Quy trình**:
1. Đọc file dưới dạng binary (bytes)
2. Trích xuất các chuỗi ASCII và Unicode
3. So sánh từng chuỗi với 3 tiêu chí
4. Lọc và sắp xếp kết quả

---

### 1.2. Bước 1: Đọc File Binary

```python
# File: backend/app/services/static_analyzer_impl.py
with open(filepath, 'rb') as f:
    file_content = f.read()  # bytes object
```

**Ví dụ cụ thể**:

Giả sử có file `malware.exe` chứa các bytes:
```
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73
2E 63 6F 6D 2F 70 61 79 6C 6F 61 64 00 00 00 00
63 6D 64 2E 65 78 65 20 2F 63 20 64 65 6C 65 74
65 20 43 3A 5C 57 69 6E 64 6F 77 73 00 00 00 00
```

**Kết quả**: `file_content` là một `bytes` object chứa tất cả các bytes trên.

---

### 1.3. Bước 2: Trích Xuất ASCII Strings

```python
# File: backend/app/services/static_analyzer_impl.py
def _extract_strings(self, content: bytes) -> List[str]:
    strings = []
    seen = set()
    current_string = []
    
    # Duyệt từng byte trong file
    for byte in content:
        if 32 <= byte <= 126:  # Printable ASCII (ký tự có thể in được)
            current_string.append(chr(byte))  # Chuyển byte → ký tự
        else:
            # Kết thúc chuỗi
            if len(current_string) >= 4:  # Tối thiểu 4 ký tự
                s = ''.join(current_string)  # Ghép thành string
                if len(s) <= 200 and s not in seen:
                    seen.add(s)
                    if self._is_suspicious_string(s):  # ← SO SÁNH Ở ĐÂY
                        strings.append(s)
            current_string = []
```

**Ví dụ cụ thể với file trên**:

**Byte sequence**: `68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73 2E 63 6F 6D 2F 70 61 79 6C 6F 61 64`

**Quá trình**:
1. Byte `68` (hex) = `104` (decimal) → `chr(104)` = `'h'`
2. Byte `74` = `116` → `chr(116)` = `'t'`
3. Byte `74` = `116` → `chr(116)` = `'t'`
4. Byte `70` = `112` → `chr(112)` = `'p'`
5. ... tiếp tục ...
6. Kết quả: `"http://malicious.com/payload"`

**Byte sequence**: `63 6D 64 2E 65 78 65 20 2F 63 20 64 65 6C 65 74 65 20 43 3A 5C 57 69 6E 64 6F 77 73`

**Kết quả**: `"cmd.exe /c delete C:\\Windows"`

---

### 1.4. Bước 3: So Sánh với Tiêu Chí Đáng Nghi Ngờ

Hàm `_is_suspicious_string(s)` thực hiện **3 loại so sánh**:

#### **A. So Sánh với Regex Patterns**

```python
# File: backend/app/services/static_analyzer_impl.py
self.suspicious_patterns = [
    r'http[s]?://[^\s]+',              # URLs
    r'ftp://[^\s]+',                    # FTP URLs
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
    r'[A-Z]:\\[^\\s]+',                 # Đường dẫn Windows
    r'\\\\[^\\s]+',                     # UNC paths
    r'HKEY_[A-Z_]+',                    # Registry keys
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
    r'[0-9a-fA-F]{32,}',                # Hex strings dài
    r'cmd\.exe|powershell|wscript|cscript',  # Command execution
    r'CreateRemoteThread|VirtualAlloc|WriteProcessMemory',  # Dangerous APIs
    r'base64|Base64',                   # Encoding
    r'password|pwd|passwd|secret|key',  # Credentials
    r'\.dll|\.exe|\.sys|\.bat|\.ps1',   # Executable files
]

def _is_suspicious_string(self, s: str) -> bool:
    # So sánh với regex patterns (không phân biệt hoa/thường)
    for pattern in self.suspicious_patterns:
        if re.search(pattern, s, re.IGNORECASE):
            return True  # Khớp → đáng ngờ
```

**Ví dụ cụ thể**:

**String**: `"http://malicious.com/payload"`

**So sánh với pattern**: `r'http[s]?://[^\s]+'`

**Giải thích pattern**:
- `http[s]?` → Khớp "http" hoặc "https"
- `://` → Khớp "://"
- `[^\s]+` → Khớp một hoặc nhiều ký tự không phải khoảng trắng

**Kết quả**: `re.search(r'http[s]?://[^\s]+', "http://malicious.com/payload", re.IGNORECASE)` → **MATCH** ✅

**Kết luận**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

**String**: `"cmd.exe /c delete C:\\Windows"`

**So sánh với pattern**: `r'cmd\.exe|powershell|wscript|cscript'`

**Giải thích pattern**:
- `cmd\.exe` → Khớp "cmd.exe" (dấu `.` được escape)
- `|` → OR operator
- `powershell` → Khớp "powershell"
- ...

**Kết quả**: `re.search(r'cmd\.exe|powershell|wscript|cscript', "cmd.exe /c delete C:\\Windows", re.IGNORECASE)` → **MATCH** ✅

**Kết luận**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

**String**: `"192.168.1.100"`

**So sánh với pattern**: `r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`

**Giải thích pattern**:
- `[0-9]{1,3}` → Khớp 1-3 chữ số
- `\.` → Khớp dấu chấm (escape)
- Lặp lại 4 lần → Khớp địa chỉ IP

**Kết quả**: `re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "192.168.1.100", re.IGNORECASE)` → **MATCH** ✅

**Kết luận**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

**String**: `"HKEY_CURRENT_USER\\Software\\Microsoft"`

**So sánh với pattern**: `r'HKEY_[A-Z_]+'`

**Giải thích pattern**:
- `HKEY_` → Khớp "HKEY_"
- `[A-Z_]+` → Khớp một hoặc nhiều chữ cái in hoa hoặc dấu gạch dưới

**Kết quả**: `re.search(r'HKEY_[A-Z_]+', "HKEY_CURRENT_USER\\Software\\Microsoft", re.IGNORECASE)` → **MATCH** ✅

**Kết luận**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

#### **B. So Sánh với Keywords**

```python
# File: backend/app/services/static_analyzer_impl.py
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

def _is_suspicious_string(self, s: str) -> bool:
    s_lower = s.lower()  # Chuyển về chữ thường
    
    # So sánh với keywords
    for keyword in self.suspicious_keywords:
        if keyword in s_lower:  # Tìm keyword trong string
            return True  # Khớp → đáng ngờ
```

**Ví dụ cụ thể**:

**String**: `"This is a malware payload"`

**So sánh với keywords**:
- `'malware' in "this is a malware payload"` → **True** ✅
- `'payload' in "this is a malware payload"` → **True** ✅

**Kết quả**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

**String**: `"Download file from server"`

**So sánh với keywords**:
- `'download' in "download file from server"` → **True** ✅
- `'server' in "download file from server"` → **True** ✅

**Kết quả**: String này **ĐÁNG NGỜ** → Thêm vào `suspicious_strings`

---

**String**: `"Hello World"`

**So sánh với keywords**:
- Tất cả keywords đều không có trong "hello world" → **False** ❌

**Kết quả**: String này **KHÔNG ĐÁNG NGỜ** → Bỏ qua

---

#### **C. So Sánh Entropy (Shannon Entropy)**

```python
# File: backend/app/services/static_analyzer_impl.py
def _has_high_entropy(self, s: str) -> bool:
    """Kiểm tra string có entropy cao (ngẫu nhiên) không"""
    import math
    
    if not s:
        return False
    
    # Tính Shannon entropy
    entropy = 0
    for char in set(s):  # Duyệt qua các ký tự duy nhất
        p = s.count(char) / len(s)  # Tần suất xuất hiện
        if p > 0:
            entropy -= p * math.log2(p)
    
    # Ngưỡng entropy cao (strings ngẫu nhiên có ~4.5-5.0 entropy)
    return entropy > 4.0

def _is_suspicious_string(self, s: str) -> bool:
    # Chỉ kiểm tra strings >= 16 ký tự
    if len(s) >= 16 and self._has_high_entropy(s):
        return True  # Entropy cao → đáng ngờ
```

**Ví dụ cụ thể**:

**String**: `"aGVsbG8gd29ybGQ="` (Base64 encoded: "hello world")

**Tính entropy**:
- Độ dài: 16 ký tự
- Các ký tự: `a`, `G`, `V`, `s`, `b`, `8`, `g`, `d`, `2`, `9`, `y`, `b`, `Q`, `=`
- Tần suất: Mỗi ký tự xuất hiện 1-2 lần
- Entropy ≈ **4.2**

**Kết quả**: `entropy > 4.0` → **True** ✅

**Kết luận**: String này **ĐÁNG NGỜ** (có thể là encoded/encrypted) → Thêm vào `suspicious_strings`

---

**String**: `"Hello World Test"`

**Tính entropy**:
- Độ dài: 16 ký tự
- Các ký tự: `H`, `e`, `l`, `o`, ` `, `W`, `r`, `d`, `T`, `s`
- Tần suất: Một số ký tự xuất hiện nhiều lần (ví dụ: `l` xuất hiện 3 lần)
- Entropy ≈ **3.2**

**Kết quả**: `entropy > 4.0` → **False** ❌

**Kết luận**: String này **KHÔNG ĐÁNG NGỜ** (entropy thấp, có thể là text bình thường) → Bỏ qua

---

**String**: `"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"` (32 ký tự ngẫu nhiên)

**Tính entropy**:
- Độ dài: 32 ký tự
- Các ký tự: Mỗi ký tự xuất hiện 1-2 lần
- Entropy ≈ **4.8**

**Kết quả**: `entropy > 4.0` → **True** ✅

**Kết luận**: String này **ĐÁNG NGỜ** (entropy cao, có thể là key/encrypted data) → Thêm vào `suspicious_strings`

---

### 1.5. Bước 4: Lọc và Sắp Xếp

```python
# File: backend/app/services/static_analyzer_impl.py
# Lọc trùng lặp
seen = set()
if s not in seen:
    seen.add(s)
    strings.append(s)

# Sắp xếp theo độ dài (dài nhất trước)
strings.sort(key=len, reverse=True)

# Giới hạn 100 strings
return strings[:100]
```

**Ví dụ**:

**Input**: 
```python
strings = [
    "http://malicious.com/payload",
    "cmd.exe",
    "http://malicious.com/payload",  # Trùng lặp
    "192.168.1.100",
    "This is a malware payload",
    "cmd.exe"  # Trùng lặp
]
```

**Sau khi lọc trùng**:
```python
strings = [
    "http://malicious.com/payload",
    "cmd.exe",
    "192.168.1.100",
    "This is a malware payload"
]
```

**Sau khi sắp xếp theo độ dài**:
```python
strings = [
    "http://malicious.com/payload",      # 30 ký tự
    "This is a malware payload",         # 26 ký tự
    "192.168.1.100",                      # 13 ký tự
    "cmd.exe"                             # 7 ký tự
]
```

**Sau khi giới hạn 100**:
```python
return strings[:100]  # Giữ tất cả (vì chỉ có 4 strings)
```

---

### 1.6. Tóm Tắt Quy Trình So Sánh Suspicious Strings

```
File Binary (bytes)
    ↓
Trích xuất ASCII/Unicode strings (4-200 ký tự)
    ↓
Với mỗi string:
    ├─→ So sánh với Regex Patterns
    │   ├─→ URLs? → ĐÁNG NGỜ ✓
    │   ├─→ IP addresses? → ĐÁNG NGỜ ✓
    │   ├─→ Commands? → ĐÁNG NGỜ ✓
    │   └─→ ... (12 patterns khác)
    │
    ├─→ So sánh với Keywords
    │   ├─→ "malware" in string? → ĐÁNG NGỜ ✓
    │   ├─→ "trojan" in string? → ĐÁNG NGỜ ✓
    │   └─→ ... (40 keywords khác)
    │
    └─→ So sánh Entropy (nếu >= 16 ký tự)
        └─→ entropy > 4.0? → ĐÁNG NGỜ ✓
    ↓
Lọc trùng lặp
    ↓
Sắp xếp theo độ dài (dài nhất trước)
    ↓
Giới hạn 100 strings
    ↓
Kết quả: suspicious_strings[]
```

---

## 2. So Sánh YARA Rules

### 2.1. Tổng Quan

**Mục đích**: So khớp file với các quy tắc YARA đã được định nghĩa để phát hiện malware.

**Quy trình**:
1. Compile YARA rules (đã làm ở startup)
2. YARA engine quét file binary
3. So khớp với từng rule (strings, hex, regex, condition)
4. Trả về các rules đã match

---

### 2.2. Bước 1: YARA Rules Structure

Mỗi YARA rule có cấu trúc:

```yara
rule RuleName {
    meta:
        description = "Mô tả rule"
        author = "Tác giả"
        reference = "Link tham khảo"
    
    strings:
        $s1 = "string1" ascii
        $s2 = "string2" wide
        $s3 = { 4D 5A }  // Hex pattern
        $s4 = /regex pattern/  // Regex pattern
    
    condition:
        $s1 and $s2 and ($s3 or $s4)
}
```

**Giải thích**:
- **meta**: Thông tin mô tả rule
- **strings**: Các patterns cần tìm (ASCII, Unicode, hex, regex)
- **condition**: Điều kiện logic (AND, OR, NOT) để rule match

---

### 2.3. Bước 2: YARA Engine Quét File

```python
# File: backend/app/services/yara_service.py
matches = self.rules.match(filepath)
```

**YARA engine làm gì**:

1. **Đọc file từ disk** (filepath)
2. **Đọc file dưới dạng binary** (bytes)
3. **Với mỗi rule**:
   - Tìm tất cả strings trong rule
   - So khớp với file binary
   - Kiểm tra condition
   - Nếu condition = True → Rule MATCH

---

### 2.4. Bước 3: So Khớp Strings

YARA hỗ trợ 4 loại strings:

#### **A. ASCII Strings**

```yara
rule Example1 {
    strings:
        $s1 = "cmd.exe" ascii
    condition:
        $s1
}
```

**Quá trình so khớp**:

**File binary**: 
```
... 63 6D 64 2E 65 78 65 ...  (bytes)
```

**YARA engine**:
1. Tìm chuỗi `"cmd.exe"` trong file
2. Chuyển "cmd.exe" → bytes: `63 6D 64 2E 65 78 65`
3. So sánh: `63 6D 64 2E 65 78 65` có trong file? → **CÓ** ✅
4. Tìm thấy ở offset: `0x1234`
5. Condition: `$s1` → **True** (đã tìm thấy)
6. **Rule MATCH** ✅

---

#### **B. Unicode Strings (Wide)**

```yara
rule Example2 {
    strings:
        $s1 = "malware" ascii
        $s2 = "malware" wide
    condition:
        $s1 or $s2
}
```

**Quá trình so khớp**:

**File binary**:
```
... 6D 00 61 00 6C 00 77 00 61 00 72 00 65 00 ...  (UTF-16 LE: "malware")
```

**YARA engine**:
1. Tìm `"malware"` ASCII: Không tìm thấy ❌
2. Tìm `"malware"` Wide (UTF-16 LE):
   - "m" = `6D 00`
   - "a" = `61 00`
   - "l" = `6C 00`
   - ...
   - Tìm thấy: `6D 00 61 00 6C 00 77 00 61 00 72 00 65 00` ✅
3. Condition: `$s1 or $s2` → **True** (vì $s2 match)
4. **Rule MATCH** ✅

---

#### **C. Hex Patterns**

```yara
rule Example3 {
    strings:
        $s1 = { 4D 5A }  // MZ header (PE file)
        $s2 = { E8 ?? ?? ?? ?? }  // CALL instruction (?? = any byte)
    condition:
        $s1 and $s2
}
```

**Quá trình so khớp**:

**File binary**:
```
4D 5A 90 00 03 00 ... E8 12 34 56 78 ...
```

**YARA engine**:
1. Tìm `{ 4D 5A }`:
   - So sánh: Bytes đầu tiên = `4D 5A`? → **CÓ** ✅
   - Tìm thấy ở offset: `0x0000`
2. Tìm `{ E8 ?? ?? ?? ?? }`:
   - `E8` = `E8`? → **CÓ** ✅
   - `??` = bất kỳ byte nào
   - Tìm thấy: `E8 12 34 56 78` ở offset `0x0010` ✅
3. Condition: `$s1 and $s2` → **True** (cả hai đều match)
4. **Rule MATCH** ✅

---

#### **D. Regex Patterns**

```yara
rule Example4 {
    strings:
        $s1 = /http[s]?:\/\/[^\s]+/  // URL pattern
    condition:
        $s1
}
```

**Quá trình so khớp**:

**File binary**:
```
... 68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73 2E 63 6F 6D ...
```

**YARA engine**:
1. Tìm regex `/http[s]?:\/\/[^\s]+/` trong file
2. Chuyển bytes → string: `"http://malicious.com"`
3. So khớp regex:
   - `http[s]?` → Khớp "http" ✅
   - `://` → Khớp "://" ✅
   - `[^\s]+` → Khớp "malicious.com" ✅
4. Tìm thấy ở offset: `0x2000` ✅
5. Condition: `$s1` → **True**
6. **Rule MATCH** ✅

---

### 2.5. Bước 4: Kiểm Tra Condition

YARA hỗ trợ các toán tử logic:

#### **AND (`and`)**

```yara
rule Example5 {
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell"
    condition:
        $s1 and $s2  // CẢ HAI phải match
}
```

**Quá trình**:
1. Tìm `$s1`: Tìm thấy ở offset `0x1000` ✅
2. Tìm `$s2`: Tìm thấy ở offset `0x2000` ✅
3. Condition: `$s1 and $s2` → **True** (cả hai đều match)
4. **Rule MATCH** ✅

**Nếu chỉ có một match**:
1. Tìm `$s1`: Tìm thấy ✅
2. Tìm `$s2`: Không tìm thấy ❌
3. Condition: `$s1 and $s2` → **False**
4. **Rule KHÔNG MATCH** ❌

---

#### **OR (`or`)**

```yara
rule Example6 {
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell"
    condition:
        $s1 or $s2  // MỘT TRONG HAI match là đủ
}
```

**Quá trình**:
1. Tìm `$s1`: Tìm thấy ✅
2. Tìm `$s2`: Không tìm thấy ❌
3. Condition: `$s1 or $s2` → **True** (vì $s1 match)
4. **Rule MATCH** ✅

---

#### **NOT (`not`)**

```yara
rule Example7 {
    strings:
        $s1 = "malware"
    condition:
        not $s1  // KHÔNG được tìm thấy $s1
}
```

**Quá trình**:
1. Tìm `$s1`: Không tìm thấy ❌
2. Condition: `not $s1` → **True** (vì $s1 không match)
3. **Rule MATCH** ✅

**Nếu tìm thấy**:
1. Tìm `$s1`: Tìm thấy ✅
2. Condition: `not $s1` → **False**
3. **Rule KHÔNG MATCH** ❌

---

#### **Kết Hợp Logic**

```yara
rule Example8 {
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell"
        $s3 = "wscript"
    condition:
        ($s1 and $s2) or $s3
}
```

**Quá trình**:
1. Tìm `$s1`: Tìm thấy ✅
2. Tìm `$s2`: Tìm thấy ✅
3. Tìm `$s3`: Không tìm thấy ❌
4. Condition: `($s1 and $s2) or $s3`
   - `($s1 and $s2)` → **True** (cả hai match)
   - `True or $s3` → **True**
5. **Rule MATCH** ✅

---

### 2.6. Ví Dụ Rule Thực Tế

```yara
rule Trojan_Generic {
    meta:
        description = "Generic trojan detection"
        author = "YARA Rule Author"
        reference = "https://..."
    
    strings:
        $s1 = "cmd.exe" ascii
        $s2 = "powershell" ascii
        $s3 = { 4D 5A }  // MZ header (PE file)
        $s4 = /http[s]?:\/\/[^\s]+/  // URL
    
    condition:
        $s1 and $s2 and $s3 and $s4
}
```

**Quá trình so khớp với file `trojan.exe`**:

**File binary**:
```
4D 5A 90 00 ... 63 6D 64 2E 65 78 65 ... 70 6F 77 65 72 73 68 65 6C 6C ...
... 68 74 74 70 3A 2F 2F 6D 61 6C 69 63 69 6F 75 73 2E 63 6F 6D ...
```

**YARA engine**:
1. Tìm `$s1` ("cmd.exe"): Tìm thấy ở `0x1000` ✅
2. Tìm `$s2` ("powershell"): Tìm thấy ở `0x2000` ✅
3. Tìm `$s3` ({ 4D 5A }): Tìm thấy ở `0x0000` ✅
4. Tìm `$s4` (regex URL): Tìm thấy ở `0x3000` ✅
5. Condition: `$s1 and $s2 and $s3 and $s4` → **True** (tất cả đều match)
6. **Rule MATCH** ✅

**Kết quả**:
```python
{
    "type": "yara",
    "rule_name": "Trojan_Generic",
    "tags": ["trojan", "generic"],
    "description": "Generic trojan detection",
    "matched_strings": [
        {"identifier": "$s1", "offset": 0x1000, "data": "cmd.exe"},
        {"identifier": "$s2", "offset": 0x2000, "data": "powershell"},
        {"identifier": "$s3", "offset": 0x0000, "data": "4D5A"},
        {"identifier": "$s4", "offset": 0x3000, "data": "http://malicious.com"}
    ]
}
```

---

### 2.7. Tóm Tắt Quy Trình So Sánh YARA Rules

```
YARA Rules (đã compile ở startup)
    ↓
YARA Engine quét file binary
    ↓
Với mỗi rule:
    ├─→ Tìm strings trong rule
    │   ├─→ ASCII strings? → So khớp bytes
    │   ├─→ Unicode strings? → So khớp UTF-16 LE
    │   ├─→ Hex patterns? → So khớp hex bytes
    │   └─→ Regex patterns? → So khớp regex
    │
    ├─→ Kiểm tra condition
    │   ├─→ AND: Tất cả strings phải match
    │   ├─→ OR: Một trong các strings match
    │   ├─→ NOT: String không được match
    │   └─→ Kết hợp: (A and B) or C
    │
    └─→ Nếu condition = True → Rule MATCH
    ↓
Trả về danh sách rules đã match
    ↓
Kết quả: yara_matches[]
```

---

## 3. So Sánh Hai Phương Pháp

### 3.1. Bảng So Sánh

| Tiêu chí | Suspicious Strings | YARA Rules |
|----------|-------------------|------------|
| **Mục đích** | Tìm strings đáng ngờ | So khớp với patterns đã định nghĩa |
| **Đọc file** | `open(filepath, 'rb')` | YARA engine tự đọc |
| **Chuyển đổi** | ❌ Không | ❌ Không |
| **So sánh** | Regex patterns, keywords, entropy | Strings, hex, regex, condition logic |
| **Kết quả** | Danh sách strings đáng ngờ | Danh sách rules đã match |
| **Độ chính xác** | Thấp (nhiều false positive) | Cao (rules được viết cẩn thận) |
| **Tốc độ** | Nhanh | Chậm hơn (nhiều rules) |
| **Cấu hình** | Hard-coded patterns/keywords | Rules file (.yar) |

### 3.2. Ưu và Nhược Điểm

#### **Suspicious Strings**

**Ưu điểm**:
- ✅ Nhanh (chỉ duyệt bytes một lần)
- ✅ Không cần rules file
- ✅ Phát hiện patterns mới (entropy)

**Nhược điểm**:
- ❌ Nhiều false positive
- ❌ Không có context (chỉ là strings)
- ❌ Khó tùy chỉnh (hard-coded)

#### **YARA Rules**

**Ưu điểm**:
- ✅ Độ chính xác cao (rules được viết cẩn thận)
- ✅ Có context (condition logic)
- ✅ Dễ tùy chỉnh (thêm/sửa rules)
- ✅ Hỗ trợ nhiều loại patterns (ASCII, Unicode, hex, regex)

**Nhược điểm**:
- ❌ Chậm hơn (phải quét nhiều rules)
- ❌ Cần rules file
- ❌ Khó phát hiện patterns mới (cần viết rule mới)

### 3.3. Khi Nào Dùng Gì?

**Dùng Suspicious Strings khi**:
- Cần phát hiện nhanh
- Không có YARA rules cho loại malware mới
- Cần phát hiện encoded/encrypted data (entropy)

**Dùng YARA Rules khi**:
- Cần độ chính xác cao
- Đã có rules cho loại malware cụ thể
- Cần phân loại malware (tags)

**Dùng cả hai khi**:
- Cần phân tích toàn diện
- Kết hợp để giảm false positive
- Bổ sung cho nhau

---

## 4. Code References

- **Suspicious Strings**: `backend/app/services/static_analyzer_impl.py`
  - `_extract_strings()`: Trích xuất strings
  - `_is_suspicious_string()`: So sánh với tiêu chí
  - `_has_high_entropy()`: Tính entropy

- **YARA Rules**: `backend/app/services/yara_service.py`
  - `scan_file()`: Quét file với YARA rules
  - `rules.match()`: YARA engine so khớp

- **YARA Rules Files**: `backend/yara_rules/rules/`
  - `index.yar`: File chính chứa tất cả rules

---

## 5. Tóm Tắt

### Suspicious Strings
1. Đọc file binary
2. Trích xuất ASCII/Unicode strings
3. So sánh với 3 tiêu chí: regex patterns, keywords, entropy
4. Lọc, sắp xếp, giới hạn

### YARA Rules
1. YARA engine đọc file binary
2. So khớp với từng rule (strings, hex, regex)
3. Kiểm tra condition logic (AND, OR, NOT)
4. Trả về rules đã match

**Cả hai đều làm việc với binary data gốc, không cần chuyển đổi!**



