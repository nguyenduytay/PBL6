# 🔍 Debug YARA Scanning

## Vấn Đề

Bạn test file có mã độc nhưng hệ thống không phát hiện. Có thể do:

1. **YARA rules không được load đúng**
2. **File test không match với bất kỳ rule nào**
3. **Lỗi trong quá trình scan nhưng không được log**

## Cách Kiểm Tra

### 1. Kiểm tra YARA rules có được load không

```bash
# Vào container backend
docker exec -it malware-backend bash

# Chạy test script
python scripts/test_yara_scan.py
```

Hoặc kiểm tra logs khi backend khởi động:
```bash
docker logs malware-backend | grep YARA
```

Bạn sẽ thấy:
- `[OK] YARA rules loaded: XXX rules` - ✅ Rules đã load
- `[WARN] YARA rules file not found` - ❌ Không tìm thấy file rules
- `[WARN] Warning loading YARA rules: ...` - ❌ Lỗi khi load

### 2. Test scan một file cụ thể

```bash
# Vào container
docker exec -it malware-backend bash

# Test scan file
python scripts/test_yara_scan.py /path/to/test/file.exe
```

### 3. Kiểm tra logs khi scan

Sau khi thêm logging, khi bạn scan file, bạn sẽ thấy trong logs:

```bash
docker logs malware-backend | grep YARA
```

Sẽ có:
- `[YARA] Scanning file: /app/uploads/xxx.exe`
- `[YARA] Found X matches for /app/uploads/xxx.exe` - ✅ Có phát hiện
- `[YARA] No matches found for /app/uploads/xxx.exe` - ⚠️ Không phát hiện

### 4. Kiểm tra YARA rules path trong Docker

```bash
docker exec -it malware-backend ls -la /app/yara_rules/rules/
docker exec -it malware-backend cat /app/yara_rules/rules/index.yar | head -20
```

## Vấn Đề Về Warning "invalid field name 'sync'"

Warning này xuất hiện vì file `MALW_AZORULT.yar` có field `sync` không hợp lệ trong YARA syntax. 

**Điều này KHÔNG ngăn YARA rules được load**, nhưng rule đó có thể không hoạt động đúng.

### Cách sửa (nếu cần):

1. Tìm file:
```bash
find yara_rules -name "*AZORULT*"
```

2. Mở file và tìm dòng 23, xóa hoặc comment field `sync`

## Debug Checklist

- [ ] YARA rules có được load không? (check logs startup)
- [ ] Có bao nhiêu rules được load? (check `[OK] YARA rules loaded: XXX rules`)
- [ ] File test có tồn tại và có quyền đọc không?
- [ ] File test có thực sự chứa malware không? (có thể test với VirusTotal)
- [ ] Có lỗi nào trong logs khi scan không? (check `[YARA] ERROR`)
- [ ] YARA rules có match với loại malware trong file test không?

## Test với File Mẫu

Nếu bạn có file malware mẫu, có thể test:

```bash
# Upload file qua API
curl -X POST "http://localhost:5000/api/scan" \
  -F "file=@test_malware.exe"

# Xem response
# Nếu malware_detected: true → ✅ Phát hiện được
# Nếu malware_detected: false → ❌ Không phát hiện
```

## Lưu Ý

1. **YARA chỉ phát hiện malware có signature trong rules** - Nếu malware mới hoặc obfuscated, có thể không phát hiện được
2. **File test phải match với patterns trong YARA rules** - Không phải mọi file malware đều match
3. **Hash-based detection** cũng được sử dụng - Kiểm tra xem hash có trong database không

## Nếu Vẫn Không Phát Hiện

1. Kiểm tra file test có thực sự là malware không (upload lên VirusTotal)
2. Kiểm tra loại malware - YARA rules có thể không có rule cho loại đó
3. Thử với file malware mẫu khác
4. Kiểm tra logs chi tiết khi scan

