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
        import sys
        from pathlib import Path
        
        # Danh sách các vị trí có thể có ember
        possible_paths = [
            # 1. Thử import từ package đã cài đặt
            None,  # Sẽ thử import trực tiếp
            # 2. Từ backend/ember (local development)
            Path(__file__).parent.parent.parent / "ember",
            # 3. Từ /app/ember (Docker container)
            Path("/app/ember"),
            # 4. Từ project root/ember
            Path(__file__).parent.parent.parent.parent / "ember",
        ]
        
        for ember_path in possible_paths:
            try:
                if ember_path is None:
                    # Thử import từ package đã cài đặt
                    import ember  # type: ignore[import-untyped]
                    from ember.features import PEFeatureExtractor  # type: ignore[import-untyped]
                    source = "installed package"
                else:
                    # Thử load từ local path
                    if not (ember_path / "__init__.py").exists():
                        continue
                    
                    # Thêm vào sys.path nếu chưa có
                    ember_parent = ember_path.parent
                    if str(ember_parent) not in sys.path:
                        sys.path.insert(0, str(ember_parent))
                    
                    # Import ember
                    import importlib
                    if 'ember' in sys.modules:
                        importlib.reload(sys.modules['ember'])
                    else:
                        import ember  # type: ignore[import-untyped]
                    
                    from ember.features import PEFeatureExtractor  # type: ignore[import-untyped]
                    source = str(ember_path)
                
                # Khởi tạo extractor với suppress warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self._extractor = PEFeatureExtractor(self.feature_version)
                
                # Thành công - return (không log để tránh spam)
                return
                
            except (ImportError, ModuleNotFoundError) as e:
                # Tiếp tục thử path tiếp theo
                continue
            except Exception as e:
                # Lỗi khác - tiếp tục thử
                continue
        
        # Không load được ember - log error
        print(f"[ERROR] Failed to load ember library from all possible paths")
        print(f"[ERROR] Tried: installed package, {Path(__file__).parent.parent.parent / 'ember'}, /app/ember")
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

