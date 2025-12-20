"""
EMBER Model - Wrapper cho EMBER LightGBM model
Load và sử dụng EMBER model để dự đoán malware từ PE files
"""
import os
import lightgbm as lgb
import numpy as np
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from app.ml.features import EmberFeatureExtractor

class EmberModel:
    """Wrapper xử lý EMBER model prediction"""
    
    def __init__(self):
        # Tên model file (chỉ dùng 1 model)
        self.model_filename = "ember_model_2018.txt"
        self.model_path = self._find_model_path()
        self.model = None
        self.extractor = EmberFeatureExtractor()
        self.threshold = 0.8336  # Ngưỡng EMBER chuẩn tại 1% FPR
        
        # Load model khi khởi tạo
        self._load_model()
        
    def _find_model_path(self) -> Path:
        """Tìm đường dẫn file model EMBER"""
        # Thư mục models nằm ở backend/models/
        models_dir = Path(__file__).parent.parent.parent / "models"
        model_path = models_dir / self.model_filename
        
        return model_path

    def _load_model(self):
        """Load LightGBM model từ file"""
        try:
            if not self.model_path.exists():
                print(f"[WARN] EMBER model file not found at {self.model_path}")
                print(f"[INFO] Vui lòng đảm bảo file model tồn tại: {self.model_filename}")
                return
            
            # Load model bằng LightGBM Booster
            self.model = lgb.Booster(model_file=str(self.model_path))
            print(f"[INFO] EMBER model loaded successfully from {self.model_path}")
            print(f"[INFO] Model name: {self.model_filename}")
            print(f"[INFO] Threshold: {self.threshold}")
            
        except Exception as e:
            # Lỗi khi load model
            print(f"[ERROR] Failed to load EMBER model: {e}")
            print(f"[ERROR] Model path: {self.model_path}")
            self.model = None
    
    def is_model_loaded(self) -> bool:
        """Kiểm tra model đã được load thành công chưa"""
        return self.model is not None
    
    def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Kiểm tra xem file có phải PE file không bằng cách đọc MZ header
        
        Args:
            file_path: Đường dẫn đến file cần kiểm tra
            
        Returns:
            Tuple (is_pe: bool, error_detail: Optional[str])
            - is_pe: True nếu file là PE (bắt đầu với 'MZ'), False nếu không
            - error_detail: Chi tiết lỗi nếu có (None nếu không có lỗi)
        """
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return False, f"File does not exist: {file_path}"
            
            file_size = file_path_obj.stat().st_size
            if file_size < 2:
                return False, f"File too small ({file_size} bytes). PE files must be at least 2 bytes (MZ header)."
            
            with open(file_path, 'rb') as f:
                header = f.read(2)
                # PE file bắt đầu với 'MZ' (0x4D5A)
                if header == b'MZ':
                    return True, None
                else:
                    # Header không đúng format PE
                    header_hex = header.hex().upper() if len(header) == 2 else "N/A"
                    return False, f"Invalid PE header. Expected 'MZ' (0x4D5A), got: {header_hex} (first 2 bytes: {header})"
        except PermissionError as e:
            return False, f"Permission denied: {str(e)}"
        except Exception as e:
            return False, f"Error reading file: {str(e)}"

    def predict(self, file_path: str) -> Dict[str, Any]:
        """
        Dự đoán file có phải malware không bằng EMBER model
        
        Args:
            file_path: Đường dẫn đến file PE
            
        Returns:
            Dict chứa kết quả dự đoán: score, is_malware, model_name
        """
        # Kiểm tra model đã load chưa
        if not self.model:
            return {
                "error": "Model not loaded", 
                "is_malware": False, 
                "score": 0.0,
                "model_name": self.model_filename
            }
        
        # Kiểm tra file có phải PE không
        is_pe, pe_error_detail = self.is_pe_file(file_path)
        if not is_pe:
            error_msg = f"File is not a valid PE file. EMBER only analyzes PE files (Portable Executable: .exe, .dll, .sys, .scr, etc.). PE files must start with 'MZ' header."
            if pe_error_detail:
                error_msg += f" Details: {pe_error_detail}"
            return {
                "error": error_msg,
                "error_detail": pe_error_detail,
                "is_malware": False,
                "score": 0.0,
                "model_name": self.model_filename,
                "file_path": str(file_path)
            }
            
        try:
            # Đọc file dưới dạng bytes
            with open(file_path, "rb") as f:
                bytez = f.read()
            
            # Trích xuất 2381 features từ file PE
            features = self.extractor.feature_vector(bytez)
            
            # Reshape để predict (1 sample, n features)
            features = features.reshape(1, -1)
            
            # Dự đoán bằng LightGBM model
            score = self.model.predict(features)[0]
            
            # So sánh với threshold để xác định malware
            return {
                "score": float(score),
                "is_malware": score > self.threshold,
                "model_name": self.model_filename,
                "threshold": self.threshold
            }
            
        except Exception as e:
            import traceback
            error_traceback = traceback.format_exc()
            print(f"[ERROR] EMBER prediction failed for {file_path}: {e}")
            print(error_traceback)
            
            # Phân loại lỗi chi tiết để dễ debug
            error_type = type(e).__name__
            error_message = str(e)
            
            # Kiểm tra các lỗi phổ biến
            if "lief" in error_message.lower() or "bad_format" in error_message.lower():
                error_detail = f"LIEF parsing error: File may be corrupted or not a valid PE file. {error_message}"
            elif "numpy" in error_message.lower() or "shape" in error_message.lower():
                error_detail = f"Feature extraction error: Invalid feature shape. {error_message}"
            elif "lightgbm" in error_message.lower() or "model" in error_message.lower():
                error_detail = f"Model prediction error: {error_message}"
            else:
                error_detail = error_message
            
            return {
                "error": error_detail,
                "error_type": error_type,
                "error_traceback": error_traceback,
                "is_malware": False, 
                "score": 0.0,
                "model_name": self.model_filename,
                "file_path": str(file_path)
            }

