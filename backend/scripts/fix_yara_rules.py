#!/usr/bin/env python3
"""
Script để tìm và sửa các file YARA có vấn đề
"""

import os
import glob
import re

def fix_yara_files():
    """Tìm và sửa các file YARA có vấn đề"""
    print("🔧 Sửa các file YARA có vấn đề...")
    
    # Tìm tất cả file YARA
    yara_files = glob.glob("yara_rules/rules/**/*.yar", recursive=True)
    yara_files.extend(glob.glob("yara_rules/rules/**/*.yara", recursive=True))
    
    fixed_count = 0
    
    for yara_file in yara_files:
        try:
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            modified = False
            
            # 1. Loại bỏ import "cuckoo"
            if 'import "cuckoo"' in content:
                content = content.replace('import "cuckoo"', '// import "cuckoo"  // Module không có sẵn')
                modified = True
                print(f"   ✅ Sửa import cuckoo trong {yara_file}")
            
            # 2. Loại bỏ cuckoo.sync.mutex
            if 'cuckoo.sync.mutex' in content:
                # Tìm và thay thế các pattern cuckoo.sync.mutex
                content = re.sub(r'cuckoo\.sync\.mutex\([^)]+\)', '', content)
                # Loại bỏ "or" thừa
                content = re.sub(r'\s+or\s*$', '', content, flags=re.MULTILINE)
                content = re.sub(r'\s+or\s*\)', ')', content)
                modified = True
                print(f"   ✅ Sửa cuckoo.sync.mutex trong {yara_file}")
            
            # 3. Loại bỏ import "pe" nếu có vấn đề
            if 'import "pe"' in content and 'pe.' not in content:
                content = content.replace('import "pe"', '// import "pe"  // Không sử dụng')
                modified = True
                print(f"   ✅ Sửa import pe trong {yara_file}")
            
            # 4. Sửa các lỗi syntax khác
            if 'sync.' in content:
                content = content.replace('sync.', '')
                modified = True
                print(f"   ✅ Sửa sync. trong {yara_file}")
            
            # Ghi file nếu có thay đổi
            if modified:
                with open(yara_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                fixed_count += 1
                
        except Exception as e:
            print(f"   ❌ Lỗi xử lý {yara_file}: {e}")
    
    print(f"\n✅ Đã sửa {fixed_count} file YARA")
    return fixed_count

def test_yara_compilation():
    """Test compile YARA rules"""
    print("\n🧪 Test compile YARA rules...")
    try:
        import yara
        
        # Thử compile từ index file
        rules = yara.compile(filepath="yara_rules/rules/index.yar")
        print("✅ Compile YARA rules thành công!")
        
        # Đếm số rules
        rule_count = 0
        for rule in rules:
            rule_count += 1
        
        print(f"📊 Tổng số rules: {rule_count}")
        
        # Test với file mẫu
        test_content = "test content for yara scanning"
        test_file = "test_yara.txt"
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        try:
            matches = rules.match(test_file)
            print(f"🧪 Test scan: {len(matches)} matches")
            for match in matches:
                print(f"   - Rule: {match.rule}")
        except Exception as e:
            print(f"⚠️ Test scan error: {e}")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)
        
        return True
        
    except ImportError:
        print("❌ yara-python chưa được cài đặt")
        return False
    except Exception as e:
        print(f"❌ Lỗi compile YARA: {e}")
        return False

def main():
    print("🚀 Malware Detector - YARA Rules Fixer")
    print("=" * 50)
    
    # Sửa các file YARA
    fixed_count = fix_yara_files()
    
    if fixed_count > 0:
        # Test compile
        if test_yara_compilation():
            print("\n✅ YARA rules đã được sửa và hoạt động!")
        else:
            print("\n⚠️ Vẫn còn lỗi trong YARA rules")
    else:
        print("\n✅ Không có file YARA nào cần sửa")

if __name__ == "__main__":
    main()
