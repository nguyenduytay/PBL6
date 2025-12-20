#!/usr/bin/env python3
"""
Script để normalize line endings cho EMBER model file
Chạy trong Docker build để đảm bảo file model có LF line endings
"""
import sys
from pathlib import Path

def normalize_model_file(model_path: str):
    """Normalize line endings cho file model"""
    model_path_obj = Path(model_path)
    
    if not model_path_obj.exists():
        print(f"[ERROR] Model file not found: {model_path}")
        sys.exit(1)
    
    # Đọc file
    print(f"[INFO] Reading model file: {model_path}")
    with open(model_path_obj, 'rb') as f:
        content = f.read()
    
    original_size = len(content)
    print(f"[INFO] Original file size: {original_size} bytes ({original_size / 1024 / 1024:.2f} MB)")
    
    # Kiểm tra file size
    if original_size < 100000000:  # < 100MB
        print(f"[ERROR] Model file too small ({original_size} bytes) - expected >100MB")
        sys.exit(1)
    
    # Kiểm tra format
    first_bytes = content[:200]
    if b'version=' not in first_bytes and b'tree=' not in first_bytes:
        print(f"[WARN] Model file may not be valid LightGBM format")
        print(f"[WARN] First 200 bytes preview: {first_bytes[:100]}")
    
    # Normalize line endings: CRLF -> LF, CR -> LF
    print(f"[INFO] Normalizing line endings...")
    normalized_content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    new_size = len(normalized_content)
    
    # Ghi lại file
    with open(model_path_obj, 'wb') as f:
        f.write(normalized_content)
    
    print(f"[INFO] Normalized: {original_size} -> {new_size} bytes ({new_size / 1024 / 1024:.2f} MB)")
    print(f"[INFO] Line endings normalized successfully")
    
    return True

if __name__ == "__main__":
    model_path = sys.argv[1] if len(sys.argv) > 1 else "models/ember_model_2018.txt"
    try:
        normalize_model_file(model_path)
    except Exception as e:
        print(f"[ERROR] Failed to normalize model file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

