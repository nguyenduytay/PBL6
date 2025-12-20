"""
EMBER Model - Wrapper cho EMBER LightGBM model
Load và sử dụng EMBER model để dự đoán malware từ PE files
"""
import lightgbm as lgb  # type: ignore[import-untyped]
import numpy as np  # type: ignore[import-untyped]
import time
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from app.ml.features import EmberFeatureExtractor

class EmberModel:
    """Wrapper xử lý EMBER model prediction"""
    
    def __init__(self):
        self.model_filename = "ember_model_2018.txt"
        self.model_path = self._find_model_path()
        self.model = None
        self.extractor = EmberFeatureExtractor()
        self.threshold = 0.8336  # Ngưỡng EMBER chuẩn tại 1% FPR
        self._load_model()
    
    def _find_model_path(self) -> Path:
        """Tìm đường dẫn file model EMBER"""
        # Vị trí mặc định: backend/models
        default_models_dir = Path(__file__).parent.parent.parent / "models"
        default_path = default_models_dir / self.model_filename
        
        # Thử các vị trí có thể (ưu tiên Docker, sau đó mặc định)
        possible_paths = [
            Path("/app/models"),  # Docker container path
            default_models_dir,  # backend/models (mặc định)
            Path("/models"),  # Alternative Docker path
        ]
        
        for models_dir in possible_paths:
            model_path = models_dir / self.model_filename
            if model_path.exists():
                if models_dir != default_models_dir:
                    print(f"[INFO] Found EMBER model at: {model_path}")
                return model_path
        
        # Trả về đường dẫn mặc định nếu không tìm thấy
        print(f"[WARN] Model not found, using default path: {default_path}")
        return default_path

    def _load_model(self):
        """Load LightGBM model từ file"""
        start_time = time.time()
        
        try:
            if not self.model_path.exists():
                print(f"[WARN] EMBER model file not found at {self.model_path}")
                return
            
            print(f"[INFO] Loading EMBER model from {self.model_path}...")
            print(f"[INFO] Model file size: {self.model_path.stat().st_size / (1024*1024):.2f} MB")
            
            self.model = lgb.Booster(model_file=str(self.model_path))
            
            elapsed = time.time() - start_time
            print(f"[INFO] EMBER model loaded successfully in {elapsed:.2f}s")
            print(f"[INFO] Model name: {self.model_filename}")
            print(f"[INFO] Threshold: {self.threshold}")
            
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"[ERROR] Failed to load EMBER model after {elapsed:.2f}s: {e}")
            self.model = None
    
    def is_model_loaded(self) -> bool:
        """Kiểm tra model đã được load thành công chưa"""
        return self.model is not None
    
    def is_pe_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Kiểm tra file có phải PE file không (kiểm tra MZ header)"""
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return False, f"File does not exist: {file_path}"
            
            file_size = file_path_obj.stat().st_size
            if file_size < 2:
                return False, f"File too small ({file_size} bytes)"
            
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header == b'MZ':
                    return True, None
                else:
                    header_hex = header.hex().upper() if len(header) == 2 else "N/A"
                    return False, f"Invalid PE header. Expected 'MZ', got: {header_hex}"
        except PermissionError as e:
            return False, f"Permission denied: {str(e)}"
        except Exception as e:
            return False, f"Error reading file: {str(e)}"

    def predict(self, file_path: str) -> Dict[str, Any]:
        """Dự đoán file có phải malware không bằng EMBER model"""
        if not self.model:
            return {
                "error": "Model not loaded", 
                "is_malware": False, 
                "score": 0.0,
                "model_name": self.model_filename
            }
        
        is_pe, pe_error_detail = self.is_pe_file(file_path)
        if not is_pe:
            error_msg = f"File is not a valid PE file. EMBER only analyzes PE files (.exe, .dll, .sys, etc.). PE files must start with 'MZ' header."
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
            with open(file_path, "rb") as f:
                bytez = f.read()
            
            features = self.extractor.feature_vector(bytez)
            
            # Kiểm tra và pad features nếu thiếu
            if len(features) != 2381:
                if len(features) < 2381:
                    padding_size = 2381 - len(features)
                    padding = np.zeros(padding_size, dtype=np.float32)
                    features = np.concatenate([features, padding])
                    print(f"[WARN] Padded {padding_size} zeros to match model dimensions")
                else:
                    truncated_count = len(features) - 2381
                    features = features[:2381]
                    print(f"[WARN] Truncated {truncated_count} features to match model dimensions")
            
            features = features.reshape(1, -1)
            score = self.model.predict(features, predict_disable_shape_check=True)[0]
            
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
            
            error_type = type(e).__name__
            error_message = str(e)
            
            if "lief" in error_message.lower() or "bad_format" in error_message.lower():
                error_detail = f"LIEF parsing error: {error_message}"
            elif "numpy" in error_message.lower() or "shape" in error_message.lower():
                error_detail = f"Feature extraction error: {error_message}"
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

