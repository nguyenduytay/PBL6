#!/usr/bin/env python3
"""
Test script để kiểm tra YARA scanning có hoạt động không
"""
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.services.yara_service import YaraService

def test_yara_loading():
    """Test xem YARA rules có được load không"""
    print("=" * 60)
    print("TEST 1: Kiểm tra YARA rules loading")
    print("=" * 60)
    
    rules = settings.get_yara_rules()
    if rules:
        try:
            rule_count = len(list(rules))
            print(f"✅ YARA rules loaded: {rule_count} rules")
            return True
        except Exception as e:
            print(f"❌ Error counting rules: {e}")
            return False
    else:
        print("❌ YARA rules NOT loaded!")
        return False

def test_yara_service():
    """Test YaraService"""
    print("\n" + "=" * 60)
    print("TEST 2: Kiểm tra YaraService")
    print("=" * 60)
    
    service = YaraService()
    if service.is_loaded():
        rule_count = service.get_rule_count()
        print(f"✅ YaraService initialized: {rule_count} rules")
        return True
    else:
        print("❌ YaraService NOT initialized!")
        return False

def test_scan_file(filepath: str):
    """Test scan một file cụ thể"""
    print("\n" + "=" * 60)
    print(f"TEST 3: Scan file: {filepath}")
    print("=" * 60)
    
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return False
    
    service = YaraService()
    if not service.is_loaded():
        print("❌ YARA rules not loaded, cannot scan")
        return False
    
    results = service.scan_file(filepath)
    
    if results:
        print(f"✅ Found {len(results)} result(s):")
        for result in results:
            print(f"  - Type: {result.get('type')}")
            if result.get('type') == 'yara':
                print(f"    Matches: {result.get('matches')}")
                print(f"    Rule count: {result.get('rule_count')}")
            elif result.get('type') == 'yara_error':
                print(f"    Error: {result.get('message')}")
        return True
    else:
        print("⚠️  No matches found (file might be clean or no matching rules)")
        return False

if __name__ == "__main__":
    print("🧪 YARA Scanning Test Script\n")
    
    # Test 1: Loading
    if not test_yara_loading():
        print("\n❌ YARA rules không được load, dừng test")
        sys.exit(1)
    
    # Test 2: Service
    if not test_yara_service():
        print("\n❌ YaraService không hoạt động, dừng test")
        sys.exit(1)
    
    # Test 3: Scan file (nếu có argument)
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        test_scan_file(test_file)
    else:
        print("\n💡 Để test scan file, chạy:")
        print(f"   python {sys.argv[0]} <path_to_file>")
        print("\n   Ví dụ:")
        print(f"   python {sys.argv[0]} test.exe")

