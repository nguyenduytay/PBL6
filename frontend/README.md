# 🎨 Frontend - Malware Detector React App

Frontend application cho hệ thống phát hiện malware sử dụng **React** và **Vite**.

## 📋 Yêu Cầu

- Node.js 16+ 
- npm hoặc yarn

## 🏗️ Cấu Trúc Dự Án

```
frontend/
│
├── 📦 src/                           # React Source Code
│   ├── main.jsx                      # ⭐ Entry point
│   ├── App.jsx                       # Main app component
│   ├── index.css                     # Global styles (Tailwind)
│   │
│   ├── 🧩 components/                # React Components
│   │   └── Layout.jsx                # Layout component (Header, Footer, Navigation)
│   │
│   ├── 📄 pages/                     # Page Components
│   │   ├── Dashboard.jsx             # Trang dashboard - Tổng quan
│   │   ├── Upload.jsx                # Trang upload file
│   │   ├── Analyses.jsx              # Danh sách analyses
│   │   └── AnalysisDetail.jsx         # Chi tiết analysis
│   │
│   └── 🔌 services/                  # API Services
│       └── api.js                     # Axios client & API functions
│
├── 📄 index.html                     # HTML entry point
├── 📦 package.json                   # Node dependencies
├── ⚙️ vite.config.js                 # Vite configuration
├── 🎨 tailwind.config.js              # Tailwind CSS configuration
├── 🎨 postcss.config.js              # PostCSS configuration
├── 🐳 Dockerfile                     # Docker configuration
└── 📝 README.md                       # File này
```

## 🚀 Cách Chạy

### Bước 1: Cài Đặt Dependencies

```bash
cd frontend
npm install
```

### Bước 2: Chạy Development Server

```bash
npm run dev
```

Ứng dụng sẽ chạy tại: **http://localhost:3000**

### Bước 3: Build Cho Production

```bash
npm run build
```

Build files sẽ được tạo trong thư mục `dist/`

### Bước 4: Preview Production Build

```bash
npm run preview
```

---

## 🔧 Cấu Hình

### API URL

Mặc định frontend sẽ gọi API tại `http://localhost:5000/api`

Để thay đổi, tạo file `.env` trong thư mục `frontend/`:

```env
VITE_API_URL=http://localhost:5000/api
```

### Vite Configuration

File `vite.config.js` đã được cấu hình:
- Port: 3000
- Proxy: `/api` → `http://localhost:5000` (backend)

### Tailwind CSS

Dự án sử dụng **Tailwind CSS** được cài đặt qua npm.

Cấu hình:
- `tailwind.config.js` - Tailwind configuration
- `postcss.config.js` - PostCSS configuration
- `src/index.css` - Tailwind directives

---

## 📦 Dependencies

### Production Dependencies
- **react** ^18.2.0 - React library
- **react-dom** ^18.2.0 - React DOM renderer
- **react-router-dom** ^6.20.0 - Routing
- **axios** ^1.6.2 - HTTP client
- **react-query** ^3.39.3 - Data fetching

### Development Dependencies
- **@vitejs/plugin-react** ^4.2.1 - Vite React plugin
- **vite** ^5.0.8 - Build tool
- **tailwindcss** ^3.4.1 - CSS framework
- **postcss** ^8.4.35 - CSS processor
- **autoprefixer** ^10.4.17 - CSS autoprefixer

---

## 🔗 API Endpoints

Frontend gọi các API sau từ backend:

### 1. Scan File
```javascript
POST /api/scan
Content-Type: multipart/form-data
```

### 2. Get Analyses
```javascript
GET /api/analyses?limit=100&offset=0
```

### 3. Get Analysis Detail
```javascript
GET /api/analyses/{id}
```

### 4. Get Statistics
```javascript
GET /api/analyses/stats/summary
```

### 5. Health Check
```javascript
GET /api/health
```

---

## 📄 Pages

### Dashboard (`/`)
- Hiển thị thống kê tổng quan
- Health check status
- Quick actions

### Upload (`/upload`)
- Upload file để quét
- Hiển thị kết quả phân tích
- Tự động chuyển đến trang chi tiết

### Analyses (`/analyses`)
- Danh sách tất cả analyses
- Bảng với pagination
- Link đến chi tiết

### Analysis Detail (`/analyses/:id`)
- Chi tiết đầy đủ của một analysis
- YARA matches
- PE information
- Suspicious strings

---

## 🎨 Styling

### Tailwind CSS

Dự án sử dụng **Tailwind CSS** cho styling:

```jsx
<div className="bg-white rounded-lg shadow p-6">
  <h1 className="text-3xl font-bold text-gray-900">Title</h1>
</div>
```

### Custom Colors

Đã cấu hình custom colors trong `tailwind.config.js`:
- `primary` - #4caf50
- `secondary` - #2196f3

---

## 🧩 Components

### Layout Component

Component chính chứa:
- Header với navigation
- Main content area
- Footer

### Page Components

Mỗi page là một component riêng:
- `Dashboard.jsx`
- `Upload.jsx`
- `Analyses.jsx`
- `AnalysisDetail.jsx`

---

## 🔌 API Service

File `src/services/api.js` chứa:
- Axios instance với base URL
- Các hàm gọi API:
  - `scanFile(file)`
  - `getAnalyses(limit, offset)`
  - `getAnalysisById(id)`
  - `getAnalysisStats()`
  - `healthCheck()`

---

## 🚀 Scripts

```bash
# Development
npm run dev          # Chạy dev server (port 3000)

# Production
npm run build        # Build cho production
npm run preview      # Preview production build
```

---

## 🐳 Docker

### Build Docker Image
```bash
docker build -t malware-detector-frontend .
```

### Run Container
```bash
docker run -p 3000:3000 malware-detector-frontend
```

---

## ⚠️ Troubleshooting

### Lỗi: Cannot find module
```bash
# Xóa node_modules và cài lại
rm -rf node_modules
npm install
```

### Lỗi: Port 3000 đã được sử dụng
Sửa trong `vite.config.js`:
```javascript
server: {
  port: 3001,  // Đổi port
}
```

### Lỗi: API connection failed
- Kiểm tra backend đang chạy tại `http://localhost:5000`
- Kiểm tra CORS configuration trong backend
- Kiểm tra `VITE_API_URL` trong `.env`

### Tailwind CSS không hoạt động
```bash
# Đảm bảo đã cài dependencies
npm install

# Kiểm tra file src/index.css có @tailwind directives
```

---

## 📚 Tài Liệu Tham Khảo

- **React**: https://react.dev/
- **Vite**: https://vitejs.dev/
- **Tailwind CSS**: https://tailwindcss.com/
- **React Router**: https://reactrouter.com/
- **Axios**: https://axios-http.com/

---

## 🎯 Tóm Tắt

- **Framework**: React 18
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Routing**: React Router
- **HTTP Client**: Axios
- **Port**: 3000
- **API URL**: http://localhost:5000/api

**Chúc bạn sử dụng thành công! 🚀**
