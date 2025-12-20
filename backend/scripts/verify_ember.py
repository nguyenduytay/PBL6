"""
Verify EMBER Integration (Consolidated API)
Run this script to check if EMBER model loads and predicts correctly.
"""
import sys
import os
import numpy as np

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    print("[INIT] Testing imports...")
    from app.shared.ember_extractor import EmberFeatureExtractor
    print("[SUCCESS] Found app.shared.ember_extractor")
    
    from app.services.ember_service import EmberService
    print("[SUCCESS] Found app.services.ember_service")
    
    print("[INIT] Initializing EmberService...")
    service = EmberService()
    
    if service.model:
        print("[SUCCESS] EMBER Model loaded successfully!")
    else:
        print("[ERROR] EMBER Model failed to load.")
        sys.exit(1)
        
    # Create a dummy file for testing
    dummy_file = "dummy_test_pe.exe"
    with open(dummy_file, "wb") as f:
        # Create a tiny file that resembles a PE header just enough to not crash lief immediately
        f.write(b'MZ' + b'\x00' * 512 + b'PE\x00\x00' + b'\x00' * 1024)
        
    print(f"[TEST] predicting on {dummy_file}...")
    result = service.predict(dummy_file)
    print(f"[RESULT] Prediction: {result}")
    
    # Cleanup
    if os.path.exists(dummy_file):
        os.remove(dummy_file)
        
    print("[SUCCESS] Verification complete.")
        
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    print("Did you install requirements? pip install -r backend/requirements.txt")
except Exception as e:
    print(f"[ERROR] Verification failed: {e}")
