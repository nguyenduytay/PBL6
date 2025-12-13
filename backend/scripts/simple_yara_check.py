#!/usr/bin/env python3
"""
Script đơn giản để kiểm tra YARA rules mà không cần import yara
"""

import os
import glob

def count_yara_files():
    """Đếm số file YARA trong dự án"""
    print("🔍 Kiểm tra YARA rules...")
    print("=" * 50)
    
    # 1. Đếm file YARA trong thư mục gốc (stub files)
    stub_files = glob.glob("yara_rules/*.yar")
    print(f"📁 File stub trong yara_rules/: {len(stub_files)}")
    
    # 2. Đếm file YARA trong thư mục rules (real rules)
    rules_files = glob.glob("yara_rules/rules/**/*.yar", recursive=True)
    yara_files = glob.glob("yara_rules/rules/**/*.yara", recursive=True)
    all_rules = rules_files + yara_files
    
    print(f"📁 File YARA thực trong yara_rules/rules/: {len(all_rules)}")
    
    # 3. Kiểm tra file index
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
    
    # 4. Phân loại rules
    print("\n📊 Phân loại rules:")
    categories = {}
    for rule_file in all_rules:
        rel_path = os.path.relpath(rule_file, "yara_rules/rules")
        category = rel_path.split(os.sep)[0] if os.sep in rel_path else "root"
        categories[category] = categories.get(category, 0) + 1
    
    for category, count in sorted(categories.items()):
        print(f"   {category}: {count} files")
    
    # 5. Kiểm tra một số file quan trọng
    important_files = [
        "yara_rules/rules/malware_index.yar",
        "yara_rules/rules/cve_rules_index.yar",
        "yara_rules/rules/exploit_kits_index.yar",
        "yara_rules/rules/webshells_index.yar"
    ]
    
    print("\n🔍 Kiểm tra file quan trọng:")
    for file_path in important_files:
        if os.path.exists(file_path):
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path}")
    
    return len(all_rules)

def main():
    print("🚀 Malware Detector - YARA Rules Checker (Simple)")
    print("=" * 60)
    
    if not os.path.exists("yara_rules"):
        print("❌ Không tìm thấy thư mục yara_rules")
        return
    
    total_rules = count_yara_files()
    
    print("\n" + "=" * 60)
    print(f"✅ Tổng cộng: {total_rules} YARA rules")
    print("💡 Để sử dụng đầy đủ, cần cài đặt yara-python:")
    print("   pip install yara-python")

if __name__ == "__main__":
    main()
