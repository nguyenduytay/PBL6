#!/usr/bin/env python3
"""
Script để kiểm tra và đếm số lượng YARA rules trong dự án
"""

import os
import yara
import glob
from pathlib import Path

def count_yara_files(directory):
    """Đếm số file YARA trong thư mục"""
    yar_files = glob.glob(os.path.join(directory, "**/*.yar"), recursive=True)
    yara_files = glob.glob(os.path.join(directory, "**/*.yara"), recursive=True)
    return yar_files + yara_files

def check_yara_rules():
    """Kiểm tra YARA rules"""
    print("🔍 Kiểm tra YARA rules...")
    print("=" * 50)
    
    # 1. Đếm file YARA
    yara_files = count_yara_files("yara_rules")
    print(f"📁 Tổng số file YARA: {len(yara_files)}")
    
    # 2. Kiểm tra file index chính
    index_file = "yara_rules/rules/index.yar"
    if os.path.exists(index_file):
        print(f"✅ File index chính: {index_file}")
        
        # Đếm số include trong file index
        with open(index_file, 'r', encoding='utf-8') as f:
            content = f.read()
            include_count = content.count('include "')
            print(f"📋 Số rules được include: {include_count}")
    else:
        print(f"❌ Không tìm thấy file index: {index_file}")
    
    # 3. Thử compile YARA rules
    print("\n🔧 Thử compile YARA rules...")
    try:
        # Thử compile từ index file
        rules = yara.compile(filepath=index_file)
        print("✅ Compile thành công từ index.yar")
        
        # Đếm số rules
        rule_count = 0
        for rule in rules:
            rule_count += 1
        
        print(f"📊 Tổng số rules đã compile: {rule_count}")
        
        # Test với một file mẫu
        test_file = "test_file.txt"
        with open(test_file, 'w') as f:
            f.write("This is a test file for YARA scanning")
        
        try:
            matches = rules.match(test_file)
            print(f"🧪 Test scan: {len(matches)} matches found")
            for match in matches:
                print(f"   - Rule: {match.rule}")
        except Exception as e:
            print(f"⚠️ Test scan error: {e}")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)
                
    except Exception as e:
        print(f"❌ Lỗi compile YARA rules: {e}")
        
        # Fallback: thử compile từng file riêng lẻ
        print("\n🔄 Thử compile từng file riêng lẻ...")
        rules_map = {}
        for yara_file in yara_files:
            if yara_file.endswith('.yar') or yara_file.endswith('.yara'):
                try:
                    # Tạo namespace từ tên file
                    namespace = os.path.splitext(os.path.basename(yara_file))[0]
                    rules_map[namespace] = yara_file
                except Exception as e:
                    print(f"⚠️ Lỗi với file {yara_file}: {e}")
        
        if rules_map:
            try:
                rules = yara.compile(filepaths=rules_map)
                print(f"✅ Compile thành công từ {len(rules_map)} files")
            except Exception as e:
                print(f"❌ Lỗi compile từ files riêng lẻ: {e}")

def main():
    print("🚀 Malware Detector - YARA Rules Checker")
    print("=" * 50)
    
    # Kiểm tra thư mục yara_rules
    if not os.path.exists("yara_rules"):
        print("❌ Không tìm thấy thư mục yara_rules")
        return
    
    check_yara_rules()
    
    print("\n" + "=" * 50)
    print("✅ Hoàn thành kiểm tra YARA rules")

if __name__ == "__main__":
    main()
