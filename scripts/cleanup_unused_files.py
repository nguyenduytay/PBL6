"""
Script để xóa các file không cần thiết
Loại bỏ file trùng lặp và dư thừa
"""
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

def remove_directory(path: Path, description: str):
    """Xóa thư mục nếu tồn tại"""
    if path.exists():
        try:
            shutil.rmtree(path)
            print(f"[OK] Removed: {description} ({path})")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to remove {path}: {e}")
            return False
    return False

def remove_file(path: Path, description: str):
    """Xóa file nếu tồn tại"""
    if path.exists():
        try:
            path.unlink()
            print(f"[OK] Removed: {description} ({path})")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to remove {path}: {e}")
            return False
    return False

def cleanup_pycache():
    """Xóa tất cả __pycache__ directories"""
    print("\n1. Cleaning __pycache__ directories...")
    count = 0
    for pycache_dir in BASE_DIR.rglob("__pycache__"):
        # Bỏ qua venv
        if "venv" in str(pycache_dir):
            continue
        if remove_directory(pycache_dir, f"__pycache__ at {pycache_dir.relative_to(BASE_DIR)}"):
            count += 1
    print(f"   Removed {count} __pycache__ directories")

def cleanup_old_templates():
    """Xóa templates cũ trong app/templates (đã migrate sang frontend/)"""
    print("\n2. Cleaning old templates in app/templates...")
    old_templates = BASE_DIR / "app" / "templates"
    if old_templates.exists():
        # Giữ lại nếu frontend/templates không tồn tại
        new_templates = BASE_DIR / "frontend" / "templates"
        if new_templates.exists():
            remove_directory(old_templates, "Old templates directory (migrated to frontend/)")
        else:
            print(f"[SKIP] Keeping app/templates (frontend/templates not found)")

def cleanup_old_static():
    """Xóa static files cũ trong app/static (đã migrate sang frontend/)"""
    print("\n3. Cleaning old static files in app/static...")
    old_static = BASE_DIR / "app" / "static"
    if old_static.exists():
        new_static = BASE_DIR / "frontend" / "static"
        if new_static.exists():
            remove_directory(old_static, "Old static directory (migrated to frontend/)")
        else:
            print(f"[SKIP] Keeping app/static (frontend/static not found)")

def cleanup_duplicate_css():
    """Xóa style.css cũ trong frontend/static/css (đã có main.css)"""
    print("\n4. Cleaning duplicate CSS files...")
    old_style = BASE_DIR / "frontend" / "static" / "css" / "style.css"
    if old_style.exists():
        main_css = BASE_DIR / "frontend" / "static" / "css" / "main.css"
        if main_css.exists():
            remove_file(old_style, "Old style.css (replaced by main.css)")

def cleanup_backend_duplicates():
    """Xóa services trùng lặp trong backend/ (đã có trong app/services/)"""
    print("\n5. Cleaning duplicate services in backend/...")
    backend_services = BASE_DIR / "backend" / "app" / "services"
    if backend_services.exists():
        app_services = BASE_DIR / "app" / "services"
        if app_services.exists():
            # Chỉ xóa nếu app/services có đầy đủ
            hash_service_exists = (app_services / "hash_service.py").exists()
            static_service_exists = (app_services / "static_analyzer_service.py").exists()
            
            if hash_service_exists and static_service_exists:
                remove_directory(backend_services, "Duplicate services in backend/ (already in app/services/)")
            else:
                print(f"[SKIP] Keeping backend/services (app/services incomplete)")

def cleanup_unnecessary_init_files():
    """Xóa __init__.py không cần thiết trong frontend/templates"""
    print("\n6. Cleaning unnecessary __init__.py files...")
    init_files = [
        BASE_DIR / "frontend" / "templates" / "__init__.py",
        BASE_DIR / "frontend" / "templates" / "components" / "__init__.py",
    ]
    
    for init_file in init_files:
        if init_file.exists():
            remove_file(init_file, f"Unnecessary __init__.py (templates don't need Python packages)")

def cleanup_empty_directories():
    """Xóa các thư mục trống"""
    print("\n7. Cleaning empty directories...")
    empty_dirs = [
        BASE_DIR / "backend" / "app" / "models",
        BASE_DIR / "backend" / "app" / "utils",
        BASE_DIR / "backend" / "tests" / "test_api",
        BASE_DIR / "backend" / "tests" / "test_services",
        BASE_DIR / "frontend" / "static" / "images" / "logos",
        BASE_DIR / "frontend" / "static" / "images" / "icons",
        BASE_DIR / "frontend" / "static" / "js" / "vendors",
        BASE_DIR / "frontend" / "templates" / "errors",
    ]
    
    for dir_path in empty_dirs:
        if dir_path.exists():
            try:
                # Chỉ xóa nếu thư mục trống
                if not any(dir_path.iterdir()):
                    remove_directory(dir_path, f"Empty directory: {dir_path.relative_to(BASE_DIR)}")
            except Exception as e:
                pass  # Ignore errors

def main():
    """Main cleanup function"""
    import sys
    import io
    # Fix encoding for Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("="*60)
    print("Cleaning Up Unused Files")
    print("="*60)
    
    cleanup_pycache()
    cleanup_old_templates()
    cleanup_old_static()
    cleanup_duplicate_css()
    cleanup_backend_duplicates()
    cleanup_unnecessary_init_files()
    cleanup_empty_directories()
    
    print("\n" + "="*60)
    print("[OK] Cleanup completed!")
    print("="*60)
    print("\n[INFO] Files removed:")
    print("  - Old templates in app/templates/")
    print("  - Old static files in app/static/")
    print("  - Duplicate style.css")
    print("  - __pycache__ directories")
    print("  - Unnecessary __init__.py files")
    print("  - Empty directories")

if __name__ == "__main__":
    main()

