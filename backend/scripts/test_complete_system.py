import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

#!/usr/bin/env python3
"""
Script test toàn bộ hệ thống Malware Detector
"""

import os
import sys
import tempfile
import asyncio

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.web_app import analyze_single_file

def test_yara_rules():
    """Test YARA rules loading"""
    print("🔍 Test YARA rules...")
    try:
        import yara
        rules = yara.compile(filepath="yara_rules/rules/index.yar")
        
        rule_count = 0
        for rule in rules:
            rule_count += 1
        
        print(f"   ✅ Loaded {rule_count} YARA rules")
        return True
    except Exception as e:
        print(f"   ❌ YARA error: {e}")
        return False

def test_malware_database():
    """Test malware database"""
    print("🔍 Test malware database...")
    try:
        from src.Database.Malware import get_malware_by_list_sha256
        
        # Test với một SHA256 giả
        result = asyncio.run(get_malware_by_list_sha256(["test_sha256"]))
        print(f"   ✅ Database connection successful")
        return True
    except Exception as e:
        print(f"   ❌ Database error: {e}")
        return False

def test_file_analysis():
    """Test file analysis"""
    print("🔍 Test file analysis...")
    try:
        # Tạo file test
        test_file = "test_malware.txt"
        with open(test_file, 'w') as f:
            f.write("This is a test file for malware detection")
        
        # Phân tích file
        result = asyncio.run(analyze_single_file(test_file))
        
        print(f"   ✅ File analysis successful")
        print(f"   📊 Results: {len(result)} items")
        
        for item in result:
            print(f"      - {item['type']}: {item.get('message', item.get('matches', 'N/A'))}")
        
        # Cleanup
        os.remove(test_file)
        return True
    except Exception as e:
        print(f"   ❌ Analysis error: {e}")
        return False

def test_web_app():
    """Test web app startup"""
    print("🔍 Test web app startup...")
    try:
        from app.web_app import app
        
        # Test route
        with app.test_client() as client:
            response = client.get('/')
            if response.status_code == 200:
                print("   ✅ Web app routes working")
                return True
            else:
                print(f"   ❌ Web app error: {response.status_code}")
                return False
    except Exception as e:
        print(f"   ❌ Web app error: {e}")
        return False

def main():
    print("🚀 Malware Detector - Complete System Test")
    print("=" * 60)
    
    tests = [
        ("YARA Rules", test_yara_rules),
        ("Malware Database", test_malware_database),
        ("File Analysis", test_file_analysis),
        ("Web App", test_web_app)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}:")
        if test_func():
            passed += 1
        else:
            print(f"   ⚠️ {test_name} failed")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("✅ All tests passed! System is ready to use.")
        print("\n🚀 To start the web application:")
        print("   python web_app.py")
        print("   Then open http://localhost:5000 in your browser")
    else:
        print("❌ Some tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    main()
