"""
EMBER Feature Extractor - Trích xuất 2381 features từ PE file
Sử dụng thư viện ember chính thức để extract features
"""
import numpy as np  # type: ignore[import-untyped]
import warnings
import os

# Suppress warnings không cần thiết
warnings.filterwarnings('ignore', category=UserWarning)
os.environ['PYTHONWARNINGS'] = 'ignore'

class EmberFeatureExtractor:
    """Trích xuất features từ file PE cho EMBER model"""
    
    def __init__(self, feature_version: int = 2):
        self.feature_version = feature_version
        self.dim = 2381
        self._extractor = None
        self._load_ember_extractor()
    
    def _load_ember_extractor(self):
        """Load PEFeatureExtractor từ thư viện ember"""
        try:
            # Thử import từ package đã cài đặt
            import ember  # type: ignore[import-untyped]
            from ember.features import PEFeatureExtractor  # type: ignore[import-untyped]
            # Suppress LIEF version warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self._extractor = PEFeatureExtractor(self.feature_version)
            return
        except ImportError as e:
            # Không có package, thử load từ source code
            pass
        except Exception as e:
            pass  # Suppress warning
        
        # Thử load từ backend/ember
        try:
            import sys
            from pathlib import Path
            
            ember_dir = Path(__file__).parent.parent.parent / "ember"
            if (ember_dir / "__init__.py").exists():
                # Thêm backend/ vào sys.path để import ember
                backend_dir = ember_dir.parent
                if str(backend_dir) not in sys.path:
                    sys.path.insert(0, str(backend_dir))
                
                # Import lại sau khi thêm vào sys.path
                import importlib
                if 'ember' in sys.modules:
                    importlib.reload(sys.modules['ember'])
                else:
                    import ember  # type: ignore[import-untyped]
                
                from ember.features import PEFeatureExtractor  # type: ignore[import-untyped]
                # Suppress LIEF version warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self._extractor = PEFeatureExtractor(self.feature_version)
        except Exception:
            self._extractor = None

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """Trích xuất 2381 features từ file PE"""
        if self._extractor is None:
            error_msg = "EMBER extractor not available - ember library not loaded"
            print(f"[ERROR] {error_msg}")
            raise RuntimeError(error_msg)
        
        try:
            features = self._extractor.feature_vector(bytez)
            features_array = np.array(features, dtype=np.float32)
            
            # Kiểm tra features có hợp lệ không
            if features_array is None or len(features_array) == 0:
                raise ValueError("Feature extraction returned empty array")
            
            # Kiểm tra features có toàn số 0 không (có thể do lỗi)
            if np.all(features_array == 0):
                # Vẫn trả về nhưng có warning - để model tự quyết định
                pass
            
            return features_array
            
        except Exception as e:
            error_msg = f"Error extracting features: {str(e)}"
            # Không trả về zero vector - throw exception để caller xử lý
            raise RuntimeError(error_msg) from e

