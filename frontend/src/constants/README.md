# Constants

Thư mục này chứa tất cả các constants được sử dụng trong ứng dụng.

## Cấu trúc

- **API Configuration**: Cấu hình API (URL, timeout)
- **File Upload Limits**: Giới hạn upload file
- **Pagination**: Cấu hình phân trang
- **File Formats**: Định dạng file được hỗ trợ
- **Date & Time**: Định dạng ngày tháng
- **UI Configuration**: Cấu hình UI (debounce, throttle, animation)
- **Rating System**: Cấu hình hệ thống đánh giá
- **Analysis Display**: Cấu hình hiển thị phân tích
- **Storage Keys**: Keys cho localStorage
- **Routes**: Định nghĩa routes
- **Export Formats**: Định dạng export
- **Badge/Button Variants**: Các biến thể UI components
- **Status Types**: Các loại trạng thái

## Sử dụng

```typescript
import { MAX_UPLOAD_SIZE_GB, API_BASE_URL, ROUTES } from '../constants'

// Sử dụng constants
const maxSize = MAX_UPLOAD_SIZE_GB
const apiUrl = API_BASE_URL
const detailRoute = ROUTES.ANALYSIS_DETAIL(123)
```

