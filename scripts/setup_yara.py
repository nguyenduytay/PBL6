#!/usr/bin/env python3
"""
Script để cài đặt và test YARA rules
"""

import subprocess
import sys
import os

def install_yara():
    """Cài đặt yara-python"""
    print("🔧 Cài đặt yara-python...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "yara-python"])
        print("✅ Cài đặt yara-python thành công")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Lỗi cài đặt yara-python: {e}")
        return False

def test_yara():
    """Test YARA rules"""
    print("\n🧪 Test YARA rules...")
    try:
        import yara
        
        # Load rules từ index file
        rules = yara.compile(filepath="yara_rules/rules/index.yar")
        print("✅ Load YARA rules thành công")
        
        # Đếm số rules
        rule_count = 0
        for rule in rules:
            rule_count += 1
        
        print(f"📊 Tổng số rules: {rule_count}")
        
        # Test với file mẫu
        test_content = b"test content for yara scanning"
        test_file = "test_yara.txt"
        with open(test_file, 'w') as f:
            f.write("test content for yara scanning")
        
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
        print(f"❌ Lỗi test YARA: {e}")
        return False

def main():
    print("🚀 Malware Detector - YARA Setup")
    print("=" * 50)
    
    # Cài đặt yara-python
    if not install_yara():
        print("❌ Không thể cài đặt yara-python")
        return
    
    # Test YARA
    if test_yara():
        print("\n✅ YARA đã sẵn sàng sử dụng!")
        print("💡 Bây giờ bạn có thể chạy web_app.py")
    else:
        print("\n❌ YARA chưa hoạt động đúng")

if __name__ == "__main__":
    main()
