"""
EMBER Model - Wrapper cho EMBER LightGBM model
Load và sử dụng EMBER model để dự đoán malware từ PE files
"""
import lightgbm as lgb  # type: ignore[import-untyped]
import numpy as np  # type: ignore[import-untyped]
import time
import os
import tempfile
import warnings
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from app.ml.features import EmberFeatureExtractor

# Suppress LightGBM warnings về unrecognized parameters
warnings.filterwarnings('ignore', message='.*unrecognized parameter.*')
warnings.filterwarnings('ignore', message='.*Ignoring unrecognized parameter.*')
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=RuntimeWarning)

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
        # Vị trí mặc định: backend/models (từ __file__)
        default_models_dir = Path(__file__).parent.parent.parent / "models"
        default_path = default_models_dir / self.model_filename
        
        # Thử các vị trí có thể (ưu tiên Docker volume mount)
        possible_paths = [
            Path("/app/models"),  # Docker container path (volume mount - ưu tiên)
            default_models_dir,  # backend/models (local development)
            Path("/models"),  # Alternative Docker path
        ]
        
        for models_dir in possible_paths:
            model_path = models_dir / self.model_filename
            if model_path.exists():
                return model_path
        
        # Trả về đường dẫn mặc định nếu không tìm thấy
        return default_path

    def _load_model(self):
        """Load LightGBM model từ file"""
        start_time = time.time()
        
        try:
            if not self.model_path.exists():
                return
            
            # Kiểm tra file size (model phải > 1MB)
            file_size = self.model_path.stat().st_size
            if file_size < 1024 * 1024:
                print(f"[ERROR] Model file too small ({file_size} bytes) - may be corrupted")
                self.model = None
                return
            
            # Kiểm tra và normalize line endings nếu cần (CRLF -> LF cho Linux)
            # Đọc một phần file để kiểm tra line endings
            needs_normalization = False
            try:
                with open(self.model_path, 'rb') as f:
                    sample = f.read(8192)  # Đọc 8KB đầu tiên
                    if b'\r\n' in sample or (b'\r' in sample and b'\n' not in sample[:100]):
                        needs_normalization = True
            except:
                pass
            
            # Load model - normalize nếu cần
            # Suppress LightGBM warnings
            try:
                if needs_normalization:
                    # Normalize toàn bộ file vào temp file
                    with open(self.model_path, 'rb') as f:
                        content = f.read()
                    content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp_file:
                        tmp_file.write(content)
                        tmp_path = tmp_file.name
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            self.model = lgb.Booster(model_file=tmp_path)
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass
                else:
                    # Load trực tiếp
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        self.model = lgb.Booster(model_file=str(self.model_path))
            except Exception as e1:
                error_msg = str(e1)
                # Nếu vẫn lỗi format, thử normalize lại
                if "Model format error" in error_msg or "expect a tree" in error_msg:
                    try:
                        with open(self.model_path, 'rb') as f:
                            content = f.read()
                        content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp_file:
                            tmp_file.write(content)
                            tmp_path = tmp_file.name
                        try:
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore")
                                self.model = lgb.Booster(model_file=tmp_path)
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except:
                                pass
                    except Exception as e2:
                        print(f"[ERROR] Failed to load EMBER model after normalization: {e2}")
                        raise e2
                else:
                    raise e1
            
            # Model loaded successfully - không cần log
            
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
            if file_size < 64:
                return False, f"File too small ({file_size} bytes). PE files must be at least 64 bytes"
            
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header == b'MZ':
                    # Kiểm tra thêm: đọc offset đến PE header (offset 0x3C)
                    f.seek(0x3C)
                    pe_offset_bytes = f.read(4)
                    if len(pe_offset_bytes) == 4:
                        pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
                        # Kiểm tra offset hợp lệ (phải < file_size)
                        if pe_offset < file_size and pe_offset > 0:
                            f.seek(pe_offset)
                            pe_signature = f.read(2)
                            if pe_signature == b'PE':
                                return True, None
                            else:
                                return False, f"Invalid PE signature at offset {pe_offset}. Expected 'PE', got: {pe_signature.hex().upper()}"
                    # Nếu không đọc được PE offset, vẫn coi là PE nếu có MZ header
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
            
            # Sử dụng ember.predict_sample() - cách chính thức
            # Suppress warnings khi predict
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                try:
                    import ember
                    if self.model is None:
                        raise ValueError("Model not loaded")
                    
                    score = ember.predict_sample(self.model, bytez, feature_version=2)
                    score = float(score)
                    
                    # Kiểm tra score = 0.0 có phải do lỗi không
                    if score == 0.0:
                        test_features = self.extractor.feature_vector(bytez)
                        if np.all(test_features == 0):
                            return {
                                "error": "Score is 0.0 and feature vector is all zeros - extraction likely failed",
                                "is_malware": False,
                                "score": 0.0,
                                "model_name": self.model_filename,
                                "file_path": str(file_path)
                            }
                        
                except (ImportError, Exception) as err:
                    # Fallback: extract features trực tiếp
                    features = self.extractor.feature_vector(bytez)
                    
                    if features is None or len(features) == 0:
                        return {
                            "error": "Feature extraction returned empty vector",
                            "is_malware": False,
                            "score": 0.0,
                            "model_name": self.model_filename,
                            "file_path": str(file_path)
                        }
                    
                    if np.all(features == 0):
                        return {
                            "error": "Feature vector contains only zeros - extraction likely failed",
                            "is_malware": False,
                            "score": 0.0,
                            "model_name": self.model_filename,
                            "file_path": str(file_path)
                        }
                    
                    # Pad/truncate features nếu cần
                    if len(features) != 2381:
                        if len(features) < 2381:
                            padding = np.zeros(2381 - len(features), dtype=np.float32)
                            features = np.concatenate([features, padding])
                        else:
                            features = features[:2381]
                    
                    features = np.array(features, dtype=np.float32)
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        score = self.model.predict([features])[0]
                    score = float(score)
            
            return {
                "score": float(score),
                "is_malware": score > self.threshold,
                "model_name": self.model_filename,
                "threshold": self.threshold
            }
            
        except Exception as e:
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
            
            print(f"[ERROR] EMBER prediction failed: {error_detail}")
            
            return {
                "error": error_detail,
                "error_type": error_type,
                "is_malware": False, 
                "score": 0.0,
                "model_name": self.model_filename,
                "file_path": str(file_path)
            }

