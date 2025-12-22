# Frontend Hiển Thị Kết Quả YARA - Giải Thích Chi Tiết

## Mục Lục

1. [Tổng Quan Flow](#tổng-quan-flow)
2. [Backend: YARA Scan và Tạo Response](#backend-yara-scan-và-tạo-response)
3. [API Response Schema](#api-response-schema)
4. [Frontend: Nhận và Hiển Thị Dữ Liệu](#frontend-nhận-và-hiển-thị-dữ-liệu)
5. [Giải Thích Tại Sao API Trả Về Như Vậy](#giải-thích-tại-sao-api-trả-về-như-vậy)
6. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

---

## Tổng Quan Flow

```
1. User upload file → Frontend
   ↓
2. Frontend gửi POST /api/v1/scan → Backend
   ↓
3. Backend: YARA Service scan file
   ↓
4. Backend: Tạo response với yara_matches và results
   ↓
5. Frontend nhận JSON response
   ↓
6. Frontend hiển thị:
   - YARA Matches Card (chi tiết từng rule)
   - Results Card (tổng hợp trong results[])
   - Severity Assessment (dựa trên số lượng matches)
```

---

## Backend: YARA Scan và Tạo Response

### 1. YARA Service Scan File

**File**: `backend/app/services/yara_service.py`

```python
def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
    # 1.1. Quét file với YARA rules
    matches = self.rules.match(filepath)
    # YARA engine quét file và trả về list các rules đã match
    
    # 1.2. Xử lý matches
    detailed_matches = []
    for match in matches:
        match_obj = {
            "rule_name": str(match.rule),  # "DebuggerException__SetConsoleCtrl"
            "tags": list(match.tags),      # ["AntiDebug", "DebuggerException"]
            "description": match.meta.get('description'),
            "author": match.meta.get('author'),
            "reference": match.meta.get('reference'),
            "matched_strings": []  # Sẽ được điền sau
        }
        
        # Extract matched strings
        for s in match.strings:
            string_info = {
                "identifier": getattr(s, 'identifier', None),  # "$s1"
                "offset": getattr(s, 'offset', None),           # 1024
                "data": getattr(s, 'data', None).hex(),         # "4d5a9000"
                "data_preview": getattr(s, 'data', None).decode('ascii', errors='ignore')  # "MZ..."
            }
            match_obj["matched_strings"].append(string_info)
        
        detailed_matches.append(match_obj)
    
    # 1.3. Tạo result object
    return [{
        "type": "yara",
        "file": filepath,
        "matches": ", ".join(match_details),  # String đơn giản
        "rule_count": len(matches),
        "detailed_matches": detailed_matches,  # Chi tiết để lưu database
        "infoUrl": None
    }]
```

**Kết quả từ YARA Service**:
```python
[
    {
        "type": "yara",
        "file": "uploads/malware.exe",
        "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, ...",
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
            },
            # ... 14 matches khác
        ],
        "infoUrl": None
    }
]
```

### 2. Analyzer Service Tổng Hợp

**File**: `backend/app/services/analyzer_service.py` (dòng 58-72)

```python
# 2.1. Gọi YARA scan
yara_results = self.yara_service.scan_file(filepath)

# 2.2. Thêm infoUrl (link tham khảo)
if yara_results and sha256:
    for result in yara_results:
        if result.get("type") == "yara" and not result.get("infoUrl"):
            result["infoUrl"] = f"https://bazaar.abuse.ch/sample/{sha256}/"

# 2.3. Thêm vào results
results.extend(yara_results)
```

**Kết quả sau khi thêm infoUrl**:
```python
[
    {
        "type": "yara",
        "matches": "...",
        "rule_count": 15,
        "detailed_matches": [...],
        "infoUrl": "https://bazaar.abuse.ch/sample/80b4182a.../"  # Đã thêm
    }
]
```

### 3. Chuẩn Bị Dữ Liệu Lưu Database

**File**: `backend/app/services/analyzer_service.py` (dòng 158-182)

```python
# 3.1. Extract detailed YARA matches từ results
yara_matches_for_db = []
for result in results:
    if result.get("type") == "yara" and result.get("detailed_matches"):
        yara_matches_for_db.extend(result.get("detailed_matches", []))

# 3.2. Tạo analysis_data
analysis_data = {
    'filename': filename,
    'sha256': sha256,
    'malware_detected': malware_detected,  # True nếu có YARA match
    'yara_matches': yara_matches_for_db,   # List các matches chi tiết
    'results': results  # Chứa YARA result với type="yara"
}
```

**Giải thích**:
- `yara_matches`: List các matches chi tiết (để hiển thị từng rule)
- `results`: Chứa YARA result tổng hợp (để hiển thị trong Results card)

### 4. Tạo API Response

**File**: `backend/app/api/v1/routes/scan.py` (dòng 50-61)

```python
# 4.1. Tạo ScanResult object
result = ScanResult(
    filename=file.filename,
    sha256=analysis_data.get("sha256"),
    md5=analysis_data.get("md5"),
    yara_matches=analysis_data.get("yara_matches", []),  # List chi tiết
    pe_info=analysis_data.get("pe_info"),
    suspicious_strings=analysis_data.get("suspicious_strings", []),
    capabilities=analysis_data.get("capabilities", []),
    malware_detected=analysis_data.get("malware_detected", False),
    analysis_time=analysis_data.get("analysis_time", 0.0),
    results=analysis_data.get("results", [])  # Chứa YARA result tổng hợp
)

return result  # FastAPI tự động serialize thành JSON
```

---

## API Response Schema

### Schema Definition

**File**: `backend/app/schemas/scan.py` (dòng 28-40)

```python
class ScanResult(BaseModel):
    """API response schema cho /api/scan"""
    filename: str
    sha256: Optional[str] = None
    md5: Optional[str] = None
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)  # YARA matches chi tiết
    pe_info: Optional[Dict[str, Any]] = None
    suspicious_strings: List[str] = Field(default_factory=list)
    capabilities: List[Dict[str, Any]] = Field(default_factory=list)
    malware_detected: bool = False
    analysis_time: float = 0.0
    results: List[Dict[str, Any]] = Field(default_factory=list)  # Chi tiết các phát hiện
```

### Ví Dụ JSON Response

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
    },
    {
      "rule_name": "anti_dbg",
      "tags": ["AntiDebug"],
      "description": "Anti-debugging techniques",
      "matched_strings": [...]
    }
    // ... 13 matches khác
  ],
  "malware_detected": true,
  "analysis_time": 2.5,
  "results": [
    {
      "type": "yara",
      "file": "uploads/malware.exe",
      "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, anti_dbg, ...",
      "rule_count": 15,
      "detailed_matches": [...],
      "infoUrl": "https://bazaar.abuse.ch/sample/80b4182a.../"
    }
  ]
}
```

### Tại Sao Có 2 Nơi Lưu YARA Data?

**1. `yara_matches[]` (top-level)**:
- **Mục đích**: Hiển thị chi tiết từng YARA rule match
- **Cấu trúc**: List các match objects với đầy đủ thông tin (rule_name, tags, description, matched_strings)
- **Sử dụng**: Frontend hiển thị trong "YARA Matches" Card

**2. `results[]` (chứa object với type="yara")**:
- **Mục đích**: Hiển thị tổng hợp trong "Detailed Results" Card
- **Cấu trúc**: Object với type="yara", matches (string), rule_count
- **Sử dụng**: Frontend hiển thị trong "Results" section cùng với Hash, EMBER results

**Lý do**:
- **Tách biệt concerns**: 
  - `yara_matches`: Chi tiết để hiển thị từng rule
  - `results`: Tổng hợp để hiển thị cùng các module khác
- **Dễ dàng mở rộng**: Có thể thêm các module khác vào `results[]` mà không ảnh hưởng `yara_matches`
- **Hiển thị linh hoạt**: Frontend có thể chọn hiển thị chi tiết hoặc tổng hợp

---

## Frontend: Nhận và Hiển Thị Dữ Liệu

### 1. Nhận Response từ API

**File**: `frontend/src/hooks/useScan.ts`

```typescript
const scan = async (file: File, scanType: ScanType = 'full') => {
  let endpoint = '/scan'
  if (scanType === 'yara') endpoint = '/scan/yara'
  if (scanType === 'ember') endpoint = '/scan/ember'
  
  const formData = new FormData()
  formData.append('file', file)
  
  // Gửi request
  const response = await axiosClient.post<ScanResponse>(endpoint, formData)
  
  // response.data có cấu trúc:
  // {
  //   filename: string
  //   yara_matches: YaraMatch[]
  //   results: Array<{type: 'yara', matches: string, ...}>
  //   malware_detected: boolean
  //   ...
  // }
  
  return response.data
}
```

### 2. Type Definitions

**File**: `frontend/src/types/index.ts` (dòng 35-49)

```typescript
export interface YaraMatch {
  rule_name: string
  tags?: string[] | string
  description?: string
  author?: string
  reference?: string
  matched_strings?: MatchedString[]
}

export interface MatchedString {
  identifier?: string
  offset?: number
  data?: string
  data_preview?: string
}

export interface Analysis {
  id: number
  filename: string
  yara_matches: YaraMatch[] | null
  results?: Array<{
    type: string
    matches?: string
    rule_count?: number
    infoUrl?: string
    // ...
  }>
  malware_detected: boolean
  // ...
}
```

### 3. Hiển Thị YARA Matches Card

**File**: `frontend/src/pages/AnalysisDetail/AnalysisDetail.tsx` (dòng 139-249)

```typescript
{/* YARA Matches Card */}
{analysis.yara_matches && Array.isArray(analysis.yara_matches) && analysis.yara_matches.length > 0 && (
  <Card
    title={`${t('analysisDetail.yaraMatches')} (${analysis.yara_matches.length})`}
    subtitle={t('analysisDetail.yaraMatchInfo')}
  >
    <div className="space-y-3">
      {analysis.yara_matches.map((match: any, index: number) => {
        // 3.1. Lấy rule name
        const ruleName = match.rule_name || match.rule || `Rule ${index + 1}`
        
        // 3.2. Xử lý tags (có thể là array hoặc string)
        let tags: string[] = []
        if (match.tags) {
          if (Array.isArray(match.tags)) {
            tags = match.tags
          } else if (typeof match.tags === 'string') {
            tags = match.tags.split(',').map(t => t.trim()).filter(t => t.length > 0)
          }
        }
        
        // 3.3. Lấy matched strings
        const matchedStrings = Array.isArray(match.matched_strings) ? match.matched_strings : []
        
        return (
          <div
            key={match.id || index}
            className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
          >
            {/* 3.4. Hiển thị rule name và description */}
            <div className="flex items-start justify-between mb-2">
              <div className="flex-1">
                <p className="font-medium text-yellow-400">{ruleName}</p>
                {match.description && (
                  <p className="text-sm text-gray-400 mt-1">{match.description}</p>
                )}
                
                {/* 3.5. Hiển thị author và reference */}
                <div className="mt-2 flex flex-wrap gap-2 items-center">
                  {match.author && (
                    <span className="text-xs text-gray-500">
                      {t('analysisDetail.author')}: {match.author}
                    </span>
                  )}
                  {match.reference && (
                    <a 
                      href={match.reference} 
                      target="_blank"
                      className="text-xs text-blue-400 hover:text-blue-300"
                    >
                      {t('analysisDetail.reference')}
                    </a>
                  )}
                </div>
              </div>
            </div>
            
            {/* 3.6. Hiển thị tags */}
            {tags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {tags.map((tag: string, tagIndex: number) => (
                  <Badge key={tagIndex} variant="warning">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
            
            {/* 3.7. Hiển thị matched strings */}
            {matchedStrings.length > 0 && (
              <div className="mt-3 pt-3 border-t border-yellow-700/50">
                <p className="text-xs font-semibold text-gray-400 mb-2">
                  {t('analysisDetail.matchedStrings')} ({matchedStrings.length}):
                </p>
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {matchedStrings.slice(0, 10).map((str: any, strIndex: number) => (
                    <div key={strIndex} className="text-xs bg-gray-800/50 p-2 rounded">
                      {str.identifier && (
                        <span className="text-yellow-300 font-mono">{str.identifier}</span>
                      )}
                      {str.offset !== undefined && (
                        <span className="text-gray-500 ml-2">
                          @0x{Number(str.offset).toString(16)}
                        </span>
                      )}
                      {str.data_preview && (
                        <code className="block text-gray-300 mt-1 break-all">
                          {str.data_preview}
                        </code>
                      )}
                    </div>
                  ))}
                  {matchedStrings.length > 10 && (
                    <p className="text-xs text-gray-500 text-center">
                      {t('analysisDetail.andMoreMatchedStrings', { count: matchedStrings.length - 10 })}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  </Card>
)}
```

**Giải thích từng phần**:

1. **Kiểm tra dữ liệu**: `analysis.yara_matches && Array.isArray(...) && ...length > 0`
2. **Map qua từng match**: Hiển thị từng YARA rule match
3. **Rule name**: Lấy từ `match.rule_name` hoặc `match.rule`
4. **Tags**: Xử lý cả array và string (từ database có thể là string)
5. **Matched strings**: Hiển thị tối đa 10 strings đầu tiên
6. **Offset**: Hiển thị dạng hex (0x400)
7. **Data preview**: Hiển thị string preview nếu có

### 4. Hiển Thị trong Results Card

**File**: `frontend/src/pages/AnalysisDetail/AnalysisDetail.tsx` (dòng 501-524)

```typescript
{/* Detailed Results */}
{analysis.results?.map((item: any, index: number) => {
  // YARA Matches
  if (item.type === 'yara') {
    return (
      <div
        key={index}
        className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
      >
        <p className="font-medium text-yellow-400 mb-1">
          {t('upload.yaraMatch')}
        </p>
        <p className="text-sm text-gray-300">{item.message || item.matches}</p>
        {item.infoUrl && (
          <a 
            href={item.infoUrl} 
            target="_blank"
            className="text-xs text-blue-400 hover:text-blue-300 mt-2 inline-block"
          >
            {t('upload.viewMore')}
          </a>
        )}
      </div>
    )
  }
  
  // ... EMBER, Hash results
})}
```

**Giải thích**:
- Hiển thị tổng hợp YARA result trong "Detailed Results" Card
- Chỉ hiển thị `item.matches` (string) và `infoUrl`
- Không hiển thị chi tiết như trong YARA Matches Card

### 5. Severity Assessment

**File**: `frontend/src/pages/AnalysisDetail/AnalysisDetail.tsx` (dòng 251-280)

```typescript
{/* Severity Assessment */}
{(() => {
  const matchCount = analysis.yara_matches?.length || 0
  const highSeverityTags = ['AntiDebug', 'PECheck', 'PEiD', 'malware', 'trojan', 'virus', 'backdoor', 'ransomware']
  
  // Kiểm tra có tag nguy hiểm không
  const hasHighSeverityTag = analysis.yara_matches?.some(m => {
    const tags = Array.isArray(m.tags) ? m.tags : (typeof m.tags === 'string' ? m.tags.split(',') : [])
    return tags.some((tag: string) => 
      highSeverityTags.some(hst => tag.toLowerCase().includes(hst.toLowerCase()))
    )
  })
  
  // Xác định severity
  let severity: 'high' | 'medium' | 'low' | 'clean' = 'clean'
  let severityText = t('analysisDetail.severityClean')
  
  if (matchCount >= 5 || hasHighSeverityTag) {
    severity = 'high'
    severityText = t('analysisDetail.severityHigh')
  } else if (matchCount >= 3) {
    severity = 'medium'
    severityText = t('analysisDetail.severityMedium')
  } else if (matchCount >= 1) {
    severity = 'low'
    severityText = t('analysisDetail.severityLow')
  }
  
  return (
    <Card title={t('analysisDetail.severityAssessment')}>
      <Badge variant={severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'success'}>
        {severityText}
      </Badge>
      <p className="text-sm text-gray-400 mt-2">
        {t('analysisDetail.severityDescription')}
      </p>
    </Card>
  )
})()}
```

**Giải thích**:
- **High**: >= 5 matches hoặc có tag nguy hiểm (AntiDebug, malware, trojan, ...)
- **Medium**: >= 3 matches
- **Low**: >= 1 match
- **Clean**: 0 matches

---

## Giải Thích Tại Sao API Trả Về Như Vậy

### 1. Tại Sao Có `yara_matches[]` và `results[]`?

**Lý do thiết kế**:

1. **Tách biệt concerns**:
   - `yara_matches[]`: Dữ liệu chi tiết để hiển thị từng rule
   - `results[]`: Dữ liệu tổng hợp để hiển thị cùng các module khác

2. **Dễ dàng mở rộng**:
   - Có thể thêm Hash, EMBER vào `results[]` mà không ảnh hưởng `yara_matches`
   - Frontend có thể xử lý từng loại result riêng biệt

3. **Hiển thị linh hoạt**:
   - YARA Matches Card: Hiển thị chi tiết từ `yara_matches[]`
   - Results Card: Hiển thị tổng hợp từ `results[]`

### 2. Tại Sao `yara_matches[]` Có Cấu Trúc Như Vậy?

**Cấu trúc**:
```typescript
{
  rule_name: string        // Tên rule
  tags: string[] | string  // Tags (có thể là array hoặc string từ database)
  description?: string      // Mô tả từ YARA rule meta
  author?: string          // Tác giả rule
  reference?: string       // Link tham khảo
  matched_strings?: []     // Các strings đã khớp
}
```

**Lý do**:
- **rule_name**: Để hiển thị tên rule
- **tags**: Để hiển thị tags và đánh giá severity
- **description**: Để giải thích rule làm gì
- **author, reference**: Để cung cấp thông tin về nguồn rule
- **matched_strings**: Để hiển thị chi tiết strings đã khớp (offset, data)

### 3. Tại Sao `results[]` Có Object Với `type="yara"`?

**Cấu trúc**:
```typescript
{
  type: "yara"              // Để frontend biết đây là YARA result
  matches: string           // String tổng hợp các matches
  rule_count: number        // Số lượng rules đã match
  infoUrl: string           // Link tham khảo
  detailed_matches: []      // Chi tiết (không dùng trong frontend)
}
```

**Lý do**:
- **type**: Để frontend phân biệt YARA, EMBER, Hash results
- **matches**: String đơn giản để hiển thị nhanh
- **rule_count**: Để hiển thị số lượng matches
- **infoUrl**: Link đến bazaar.abuse.ch để xem thêm thông tin

### 4. Tại Sao Có `infoUrl`?

**File**: `backend/app/services/analyzer_service.py` (dòng 66-70)

```python
# Thêm link tham khảo từ bazaar.abuse.ch
if yara_results and sha256:
    for result in yara_results:
        if result.get("type") == "yara" and not result.get("infoUrl"):
            result["infoUrl"] = f"https://bazaar.abuse.ch/sample/{sha256}/"
```

**Lý do**:
- **Bazaar.abuse.ch**: Là database công khai về malware samples
- **SHA256**: Dùng để tìm sample trên bazaar
- **Mục đích**: Cho phép user xem thêm thông tin về file malware

### 5. Tại Sao `tags` Có Thể Là Array Hoặc String?

**Lý do**:
- **Từ YARA**: `tags` là array `["AntiDebug", "DebuggerException"]`
- **Từ Database**: `tags` được lưu dưới dạng string `"AntiDebug, DebuggerException"` (comma-separated)
- **Frontend xử lý**: Kiểm tra cả array và string để tương thích

**Code xử lý**:
```typescript
let tags: string[] = []
if (match.tags) {
  if (Array.isArray(match.tags)) {
    tags = match.tags
  } else if (typeof match.tags === 'string') {
    tags = match.tags.split(',').map(t => t.trim()).filter(t => t.length > 0)
  }
}
```

---

## Ví Dụ Thực Tế

### Ví Dụ 1: File Có 15 YARA Matches

**API Response**:
```json
{
  "filename": "malware.exe",
  "yara_matches": [
    {
      "rule_name": "DebuggerException__SetConsoleCtrl",
      "tags": ["AntiDebug", "DebuggerException"],
      "description": "Detects debugger evasion",
      "matched_strings": [
        {
          "identifier": "$s1",
          "offset": 1024,
          "data_preview": "MZ..."
        }
      ]
    },
    // ... 14 matches khác
  ],
  "results": [
    {
      "type": "yara",
      "matches": "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, ...",
      "rule_count": 15,
      "infoUrl": "https://bazaar.abuse.ch/sample/80b4182a.../"
    }
  ],
  "malware_detected": true
}
```

**Frontend Hiển Thị**:

1. **YARA Matches Card**:
   - Title: "YARA Matches (15)"
   - Hiển thị 15 cards, mỗi card một rule:
     - Rule name: "DebuggerException__SetConsoleCtrl"
     - Tags: [AntiDebug, DebuggerException] (badges màu vàng)
     - Description: "Detects debugger evasion"
     - Matched strings: "$s1 @0x400 MZ..."

2. **Results Card**:
   - Hiển thị 1 card với:
     - Type: "YARA Match"
     - Message: "DebuggerException__SetConsoleCtrl (tags: AntiDebug) - Detects debugger evasion, ..."
     - Link: "View More" → bazaar.abuse.ch

3. **Severity Assessment**:
   - Severity: "High" (vì >= 5 matches và có tag "AntiDebug")
   - Badge màu đỏ

### Ví Dụ 2: File Không Có YARA Matches

**API Response**:
```json
{
  "filename": "clean_file.exe",
  "yara_matches": [],
  "results": [],
  "malware_detected": false
}
```

**Frontend Hiển Thị**:

1. **YARA Matches Card**: Không hiển thị (vì `yara_matches.length === 0`)

2. **Results Card**: Không có YARA result

3. **Severity Assessment**: "Clean" (badge màu xanh)

---

## Tóm Tắt

### Flow Từ Backend Đến Frontend

1. **YARA Service**: Scan file → Trả về `detailed_matches[]`
2. **Analyzer Service**: Tổng hợp → Tạo `yara_matches[]` và `results[]`
3. **API Route**: Tạo `ScanResult` → Trả về JSON
4. **Frontend**: Nhận JSON → Hiển thị trong 2 cards:
   - YARA Matches Card (từ `yara_matches[]`)
   - Results Card (từ `results[]`)

### Căn Cứ Trả Về Dữ Liệu

1. **YARA Engine**: Trả về matches với rule name, tags, strings
2. **Database Schema**: Lưu `yara_matches` dưới dạng JSON
3. **API Schema**: Định nghĩa `ScanResult` với `yara_matches[]` và `results[]`
4. **Frontend Types**: Định nghĩa `YaraMatch` interface
5. **UI Requirements**: Cần hiển thị chi tiết và tổng hợp

### Tại Sao Thiết Kế Như Vậy

- **Tách biệt concerns**: Chi tiết vs Tổng hợp
- **Dễ mở rộng**: Thêm module mới không ảnh hưởng YARA
- **Linh hoạt**: Frontend có thể chọn hiển thị chi tiết hoặc tổng hợp
- **Tương thích**: Xử lý cả array và string cho tags

---

**Tài liệu này giải thích chi tiết cách frontend hiển thị YARA results và tại sao API trả về dữ liệu như vậy.**

