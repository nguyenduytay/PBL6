# Mô tả Giao diện Người dùng

## 3.3.2. Giao diện người dùng

Hệ thống cung cấp giao diện web trực quan, thân thiện với người dùng, được thiết kế nhằm hỗ trợ đầy đủ các thao tác trong quá trình upload, phân tích, theo dõi và quản lý kết quả phát hiện mã độc. Giao diện được xây dựng theo hướng hiện đại, dễ sử dụng và hỗ trợ cập nhật trạng thái xử lý khi người dùng thao tác.

### Dashboard

Trang Dashboard hiển thị tổng quan trạng thái của hệ thống, bao gồm số lượng file đã được quét, số lượng file được xác định là mã độc, số file sạch, và số file quét trong 24h gần nhất. Các thống kê được hiển thị dưới dạng StatCard với icon và màu sắc phân biệt (xanh lá cho file sạch, đỏ cho malware, xanh dương cho tổng số). Ngoài ra, dashboard còn cung cấp các hành động nhanh như upload file mới hoặc truy cập lịch sử phân tích (Quick Actions Card), giúp người dùng thao tác thuận tiện và nhanh chóng. Dashboard cũng hiển thị health check status và system info để người dùng theo dõi trạng thái kết nối với backend và thông tin hệ thống.

**Tính năng:**
- **Hiển thị tổng quan hệ thống**: Số lượng file đã quét, số lượng malware phát hiện, số file sạch, số file quét trong 24h gần nhất
- **Cung cấp các hành động nhanh**: Upload file, xem lịch sử phân tích (Quick Actions Card)
- **Thống kê trực quan**: Hiển thị dạng StatCard với icon và màu sắc phân biệt
- **Health check status**: Hiển thị trạng thái kết nối với backend (Health Status Card)
- **System Info**: Hiển thị thông tin hệ thống (System Info Card)

### Upload & Scan

Chức năng Upload & Scan cho phép người dùng tải lên file cần phân tích dưới dạng file đơn lẻ. Người dùng có thể lựa chọn chế độ quét phù hợp, bao gồm: quét bằng YARA, phân tích bằng mô hình Machine Learning (EMBER), hoặc chế độ quét đầy đủ kết hợp YARA, Machine Learning, kiểm tra hash và phân tích tĩnh PE file. Giao diện hỗ trợ kéo thả file trực tiếp (drag & drop), hiển thị tiến trình quét (loading spinner và thông báo trạng thái) và trả về kết quả ngay sau khi quá trình phân tích hoàn tất.

**Tính năng:**
- **Upload file đơn lẻ**: Quét một file với các tùy chọn:
  - **YARA only**: Chỉ quét bằng YARA rules
  - **EMBER only**: Chỉ phân tích bằng mô hình ML
  - **Full scan** (mặc định): Kết hợp YARA + EMBER + Hash + Static Analysis
- **Hỗ trợ drag & drop**: Kéo thả file trực tiếp vào giao diện
- **Hiển thị tiến trình quét**: Loading spinner và thông báo trạng thái khi đang quét
- **Kết quả trả về ngay** sau khi quét, bao gồm:
  - Thông tin YARA matches (rule name, tags, matched strings)
  - Hash values (SHA256, MD5, SHA1)
  - PE information (sections, imports, exports, entropy)
  - Suspicious strings
  - EMBER score và prediction

### Batch Scan

Chức năng Batch Scan hỗ trợ quét đồng thời nhiều file theo cơ chế xử lý bất đồng bộ, giúp nâng cao hiệu suất khi phân tích số lượng lớn mẫu. Người dùng có thể upload toàn bộ folder và hệ thống sẽ quét tất cả file bên trong. Tiến trình quét được cập nhật thông qua polling (người dùng click "Check Status") và hiển thị dưới dạng bảng tổng hợp, trong đó thể hiện rõ trạng thái xử lý của từng file (đang xử lý, hoàn thành hoặc lỗi).

**Tính năng:**
- **Upload và quét nhiều file cùng lúc**:
  - **Scan Folder**: Upload toàn bộ folder (hỗ trợ lọc theo extension)
- **Kết hợp YARA + EMBER**: Batch scan tự động sử dụng **cả hai phương pháp** (YARA + EMBER + Hash + Static Analysis) cho mỗi file
- **Xử lý bất đồng bộ**: Quét nhiều file song song trong background task
- **Theo dõi tiến trình**: Hiển thị trạng thái qua polling (người dùng có thể click "Check Status"):
  - Tổng số file
  - Số file đã xử lý
  - Số file hoàn thành
  - Số file lỗi
  - Batch ID để theo dõi
- **Kết quả tổng hợp**: Bảng kết quả với:
  - Tên file
  - Hash (SHA256)
  - Trạng thái (Malware/Clean)

### Analysis Results (Analysis Detail)

Trang Analysis Results hiển thị chi tiết kết quả phân tích của từng file, bao gồm danh sách các rule YARA khớp với đầy đủ thông tin (tên, mô tả, tác giả, reference, chuỗi khớp), thông tin entropy của các section, các chuỗi đáng ngờ, điểm số và kết quả dự đoán của mô hình EMBER, cũng như các thông tin phân tích tĩnh PE file (sections, imports, exports). Người dùng có thể đánh giá mức độ nghiêm trọng của file (High, Medium, Low) và xem phân loại malware (Trojan, Ransomware, Backdoor, InfoStealer, Keylogger) dựa trên YARA tags.

**Tính năng:**
- **Hiển thị chi tiết kết quả phân tích**:
  - Rule YARA khớp với đầy đủ thông tin (tên, mô tả, tác giả, reference, chuỗi khớp với offset và data preview)
  - Entropy các section
  - Chuỗi đáng ngờ được phát hiện
  - Kết quả dự đoán ML (EMBER score, threshold, classification)
  - PE information (imports, exports, sections, timestamp, machine type)
- **Severity assessment**: Đánh giá mức độ nghiêm trọng (High/Medium/Low) dựa trên số lượng YARA matches và tags
- **Malware classification**: Phân loại malware (Trojan, Ransomware, Backdoor, InfoStealer, Keylogger) dựa trên YARA tags
- **Rating system**: Người dùng có thể đánh giá chất lượng phân tích với rating 1-5 sao và bình luận
- **Rating statistics**: Hiển thị tổng số ratings, điểm trung bình, và phân bố ratings

### History & Rating (Analyses)

Chức năng History & Rating cho phép hệ thống lưu trữ toàn bộ kết quả phân tích trước đó. Người dùng có thể tìm kiếm, lọc và phân trang các bản ghi phân tích theo nhiều tiêu chí khác nhau. Bên cạnh đó, hệ thống hỗ trợ người dùng đánh giá chất lượng kết quả phân tích thông qua cơ chế rating (1–5 sao) và bình luận, góp phần cải thiện và đánh giá độ tin cậy của hệ thống.

**Tính năng:**
- **Lưu trữ toàn bộ kết quả phân tích** trước đó
- **Hiển thị dạng bảng** với các cột:
  - ID, Tên file, Hash (SHA256), Trạng thái, Ngày quét
  - Số lượng YARA matches, EMBER score
- **Phân trang**: Hỗ trợ phân trang với số lượng items tùy chọn (10, 20, 50, 100)
- **Tìm kiếm và lọc**:
  - Theo tên file
  - Theo hash (SHA256, MD5)
  - Theo ngày quét
  - Theo trạng thái (malware/benign)
- **Quản lý analyses**:
  - Xóa analysis đơn lẻ
  - Xóa nhiều analyses cùng lúc (bulk delete)
  - Chọn tất cả / Bỏ chọn
- **Export Data**: Xuất dữ liệu phân tích ra nhiều định dạng (CSV, JSON, Excel) thông qua ExportButtons component
- **Đánh giá chất lượng phân tích**:
  - Rating 1–5 sao (trong Analysis Detail page)
  - Thêm bình luận và reviewer name
  - Xem thống kê ratings

### Search

Trang Search cung cấp tính năng tìm kiếm toàn văn trong tất cả analyses, hỗ trợ infinite scroll để tự động tải thêm kết quả khi cuộn xuống. Người dùng có thể tìm kiếm theo nhiều tiêu chí như tên file, hash (SHA256, MD5), hoặc nội dung phân tích. Kết quả được hiển thị với preview thông tin và tổng số kết quả cùng số lượng đã tải.

**Tính năng:**
- **Tìm kiếm toàn văn** trong tất cả analyses
- **Infinite scroll**: Tự động tải thêm kết quả khi cuộn xuống
- **Tìm kiếm theo nhiều tiêu chí**:
  - Tên file
  - Hash (SHA256, MD5)
  - Nội dung phân tích
- **Hiển thị kết quả** với preview thông tin
- **Tổng số kết quả** và số lượng đã tải

### Đa ngôn ngữ

Giao diện người dùng hỗ trợ đa ngôn ngữ, cho phép chuyển đổi linh hoạt giữa Tiếng Việt, Tiếng Anh và Tiếng Trung. Với thiết kế responsive, giao diện hoạt động ổn định trên nhiều loại thiết bị khác nhau như máy tính để bàn, máy tính bảng và điện thoại di động, đồng thời hỗ trợ cập nhật trạng thái xử lý khi người dùng thao tác (polling qua button "Check Status" cho batch scan).

**Tính năng:**
- **Hỗ trợ 3 ngôn ngữ**:
  - 🇻🇳 Tiếng Việt
  - 🇬🇧 Tiếng Anh
  - 🇨🇳 Tiếng Trung
- **Chuyển đổi ngôn ngữ trực tiếp** trên giao diện qua language switcher
- **Tự động lưu** lựa chọn ngôn ngữ của người dùng (localStorage)

### Tính năng bổ sung

**Tính năng chung:**
- **Batch Scan**: Upload và quét nhiều file cùng lúc (folder)
- **Progress Tracking**: Theo dõi tiến trình quét qua polling (check status button)
- **Export Data**: Xuất dữ liệu phân tích ra nhiều định dạng (CSV, JSON, Excel) - có ExportButtons component trong trang Analyses
- **Phân trang**: Hỗ trợ phân trang cho danh sách analyses với các tùy chọn số lượng items
- **Infinite Scroll**: Tự động tải thêm kết quả khi tìm kiếm
- **Bulk Operations**: Xóa nhiều analyses cùng lúc
- **Responsive Design**: Giao diện tối ưu cho mọi thiết bị (desktop, tablet, mobile)
- **Navigation**: Điều hướng dễ dàng giữa các trang với sidebar menu
- **Error Handling**: Xử lý lỗi và hiển thị thông báo rõ ràng
- **Loading States**: Hiển thị trạng thái loading cho mọi thao tác
- **Dark Theme**: Giao diện tối (dark mode) với màu sắc phù hợp

## Tổng kết

Hệ thống cung cấp giao diện web hoàn chỉnh với đầy đủ tính năng để hỗ trợ người dùng trong quá trình phát hiện và phân tích malware. Giao diện được thiết kế hiện đại, thân thiện, hỗ trợ đa ngôn ngữ và responsive, đảm bảo trải nghiệm người dùng tốt trên mọi thiết bị.

