# -*- coding: utf-8 -*-
"""
Script test de kiem tra du an hoat dong dung chua
"""
import sys
import os
from pathlib import Path

# Set UTF-8 encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

def test_imports():
    """Test import các modules chính"""
    print("=" * 60)
    print("TEST 1: Kiểm tra imports")
    print("=" * 60)
    
    try:
        from app.main import app
        print("[OK] app.main imported successfully")
    except Exception as e:
        print(f"[FAIL] Failed to import app.main: {e}")
        return False
    
    try:
        from app.core.config import settings
        print("[OK] app.core.config imported successfully")
    except Exception as e:
        print(f"[FAIL] Failed to import app.core.config: {e}")
        return False
    
    try:
        from app.api.v1 import api_router
        print("[OK] app.api.v1 imported successfully")
    except Exception as e:
        print(f"[FAIL] Failed to import app.api.v1: {e}")
        return False
    
    try:
        from app.services.analyzer_service import AnalyzerService
        print("[OK] app.services.analyzer_service imported successfully")
    except Exception as e:
        print(f"[FAIL] Failed to import analyzer_service: {e}")
        return False
    
    try:
        from app.database.connection import init_db
        print("[OK] app.database.connection imported successfully")
    except Exception as e:
        print(f"[FAIL] Failed to import database.connection: {e}")
        return False
    
    return True

def test_api_routes():
    """Test API routes được đăng ký"""
    print("\n" + "=" * 60)
    print("TEST 2: Kiểm tra API routes")
    print("=" * 60)
    
    try:
        from app.main import app
        
        routes = []
        for route in app.routes:
            if hasattr(route, 'path') and hasattr(route, 'methods'):
                routes.append({
                    'path': route.path,
                    'methods': list(route.methods)
                })
        
        print(f"[OK] Found {len(routes)} routes:")
        for route in routes:
            methods = ', '.join(route['methods'])
            print(f"   {methods:15} {route['path']}")
        
        # Kiểm tra các routes quan trọng
        important_routes = [
            '/api/health',
            '/api/scan',
            '/api/analyses',
            '/api/docs',
        ]
        
        route_paths = [r['path'] for r in routes]
        for important_route in important_routes:
            if important_route in route_paths:
                print(f"[OK] Route {important_route} found")
            else:
                print(f"[WARN]  Route {important_route} not found")
        
        return True
    except Exception as e:
        print(f"[FAIL] Failed to check routes: {e}")
        return False

def test_cors_config():
    """Test CORS configuration"""
    print("\n" + "=" * 60)
    print("TEST 3: Kiểm tra CORS configuration")
    print("=" * 60)
    
    try:
        from app.main import app
        
        # Kiểm tra middleware
        has_cors = False
        for middleware in app.user_middleware:
            if 'CORSMiddleware' in str(middleware):
                has_cors = True
                print("[OK] CORS middleware found")
                break
        
        if not has_cors:
            print("[FAIL] CORS middleware not found")
            return False
        
        return True
    except Exception as e:
        print(f"[FAIL] Failed to check CORS: {e}")
        return False

def test_settings():
    """Test settings configuration"""
    print("\n" + "=" * 60)
    print("TEST 4: Kiểm tra Settings")
    print("=" * 60)
    
    try:
        from app.core.config import settings
        
        print(f"[OK] APP_NAME: {settings.APP_NAME}")
        print(f"[OK] APP_VERSION: {settings.APP_VERSION}")
        print(f"[OK] HOST: {settings.HOST}")
        print(f"[OK] PORT: {settings.PORT}")
        print(f"[OK] API_V1_STR: {settings.API_V1_STR}")
        print(f"[OK] UPLOAD_FOLDER: {settings.UPLOAD_FOLDER}")
        print(f"[OK] YARA_RULES_PATH: {settings.YARA_RULES_PATH}")
        
        # Kiểm tra YARA rules path
        if settings.YARA_RULES_PATH.exists():
            print(f"[OK] YARA rules file exists: {settings.YARA_RULES_PATH}")
        else:
            print(f"[WARN]  YARA rules file not found: {settings.YARA_RULES_PATH}")
        
        return True
    except Exception as e:
        print(f"[FAIL] Failed to check settings: {e}")
        return False

def test_frontend_structure():
    """Test frontend structure"""
    print("\n" + "=" * 60)
    print("TEST 5: Kiểm tra Frontend Structure")
    print("=" * 60)
    
    frontend_path = Path(__file__).parent / "frontend"
    
    required_files = [
        "package.json",
        "vite.config.js",
        "index.html",
        "src/main.jsx",
        "src/App.jsx",
        "src/services/api.js",
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = frontend_path / file_path
        if full_path.exists():
            print(f"[OK] {file_path} exists")
        else:
            print(f"[FAIL] {file_path} not found")
            all_exist = False
    
    required_dirs = [
        "src/components",
        "src/pages",
        "src/services",
    ]
    
    for dir_path in required_dirs:
        full_path = frontend_path / dir_path
        if full_path.exists():
            print(f"[OK] {dir_path}/ exists")
        else:
            print(f"[FAIL] {dir_path}/ not found")
            all_exist = False
    
    return all_exist

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("KIEM TRA DU AN MALWARE DETECTOR")
    print("=" * 60 + "\n")
    
    results = []
    
    # Test backend
    results.append(("Backend Imports", test_imports()))
    results.append(("API Routes", test_api_routes()))
    results.append(("CORS Config", test_cors_config()))
    results.append(("Settings", test_settings()))
    
    # Test frontend
    results.append(("Frontend Structure", test_frontend_structure()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TỔNG KẾT")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[OK] PASS" if result else "[FAIL] FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nKết quả: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] Tất cả tests đều PASS! Dự án sẵn sàng chạy.")
        return 0
    else:
        print(f"\n[WARN]  Có {total - passed} test(s) failed. Vui lòng kiểm tra lại.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

