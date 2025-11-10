"""
Script migration cấu trúc dự án
Di chuyển files vào cấu trúc mới: frontend/ và backend/
"""
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

def create_directories():
    """Tạo các thư mục mới"""
    dirs = [
        "frontend/templates/components",
        "frontend/templates/pages",
        "frontend/templates/errors",
        "frontend/static/css/components",
        "frontend/static/css/themes",
        "frontend/static/js/modules",
        "frontend/static/js/vendors",
        "frontend/static/images/logos",
        "frontend/static/images/icons",
        "backend/app/models",
        "backend/app/utils",
        "backend/tests/test_api",
        "backend/tests/test_services",
    ]
    
    for dir_path in dirs:
        full_path = BASE_DIR / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"[OK] Created: {dir_path}")

def migrate_templates():
    """Di chuyển templates"""
    templates_dir = BASE_DIR / "app" / "templates"
    pages_dir = BASE_DIR / "frontend" / "templates" / "pages"
    
    if templates_dir.exists():
        for file in templates_dir.glob("*.html"):
            if file.name not in ["base.html"]:  # Giữ base.html ở root templates
                shutil.copy2(file, pages_dir / file.name)
                print(f"[OK] Copied template: {file.name}")
        
        # Copy base.html vào frontend/templates
        base_file = templates_dir / "base.html"
        if base_file.exists():
            shutil.copy2(base_file, BASE_DIR / "frontend" / "templates" / "base.html")
            print(f"[OK] Copied: base.html")

def migrate_static():
    """Di chuyển static files"""
    static_dir = BASE_DIR / "app" / "static"
    frontend_static = BASE_DIR / "frontend" / "static"
    
    if static_dir.exists():
        # Copy CSS
        css_dir = static_dir / "css"
        if css_dir.exists():
            for file in css_dir.glob("*.css"):
                shutil.copy2(file, frontend_static / "css" / file.name)
                print(f"[OK] Copied CSS: {file.name}")
        
        # Copy JS
        js_dir = static_dir / "js"
        if js_dir.exists():
            for file in js_dir.glob("*.js"):
                shutil.copy2(file, frontend_static / "js" / file.name)
                print(f"[OK] Copied JS: {file.name}")
        
        # Copy images
        images_dir = static_dir / "images"
        if images_dir.exists():
            for file in images_dir.rglob("*"):
                if file.is_file():
                    rel_path = file.relative_to(images_dir)
                    dest = frontend_static / "images" / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file, dest)
                    print(f"[OK] Copied image: {rel_path}")

def update_config_paths():
    """Cập nhật paths trong config"""
    config_file = BASE_DIR / "app" / "core" / "config.py"
    
    if config_file.exists():
        content = config_file.read_text(encoding='utf-8')
        
        # Cập nhật TEMPLATES_DIR
        old_template = 'TEMPLATES_DIR = BASE_DIR / "app" / "templates"'
        new_template = 'TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"'
        if old_template in content:
            content = content.replace(old_template, new_template)
            print("[OK] Updated TEMPLATES_DIR in config.py")
        
        config_file.write_text(content, encoding='utf-8')

def update_main_static():
    """Cập nhật static files mount trong main.py"""
    main_file = BASE_DIR / "app" / "main.py"
    
    if main_file.exists():
        content = main_file.read_text(encoding='utf-8')
        
        # Cập nhật static_dir path
        old_static = 'static_dir = Path(__file__).parent / "static"'
        new_static = 'static_dir = BASE_DIR / "frontend" / "static"'
        
        if old_static in content:
            # Thêm BASE_DIR import nếu chưa có
            if 'BASE_DIR = Path(__file__).parent.parent.parent' not in content:
                content = content.replace(
                    'from pathlib import Path',
                    'from pathlib import Path\nBASE_DIR = Path(__file__).parent.parent.parent'
                )
            
            content = content.replace(old_static, new_static)
            print("[OK] Updated static_dir in main.py")
        
        main_file.write_text(content, encoding='utf-8')

def main():
    """Main migration function"""
    import sys
    import io
    # Fix encoding for Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("="*60)
    print("Starting Project Structure Migration")
    print("="*60)
    
    print("\n1. Creating new directory structure...")
    create_directories()
    
    print("\n2. Migrating templates...")
    migrate_templates()
    
    print("\n3. Migrating static files...")
    migrate_static()
    
    print("\n4. Updating configuration paths...")
    update_config_paths()
    update_main_static()
    
    print("\n" + "="*60)
    print("[OK] Migration completed!")
    print("="*60)
    print("\n[WARN] IMPORTANT: Please test the application:")
    print("   python -m uvicorn app.main:app --reload")
    print("\n📝 Next steps:")
    print("   1. Test all routes")
    print("   2. Check static files load correctly")
    print("   3. Update any remaining imports if needed")

if __name__ == "__main__":
    main()

