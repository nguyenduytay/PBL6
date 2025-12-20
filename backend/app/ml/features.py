"""
EMBER Feature Extractor - Trích xuất 2381 features từ PE file
Sử dụng thư viện ember chính thức để extract features
"""
import numpy as np  # type: ignore[import-untyped]

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
            self._extractor = PEFeatureExtractor(self.feature_version)
            print(f"[INFO] ember library loaded from installed package")
            return
        except ImportError as e:
            # Không có package, thử load từ source code
            pass
        except Exception as e:
            print(f"[WARN] Error importing ember package: {e}")
        
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
                self._extractor = PEFeatureExtractor(self.feature_version)
                print(f"[INFO] ember library loaded from: {ember_dir}")
            else:
                print(f"[WARN] ember library not found at {ember_dir}")
        except Exception as e:
            import traceback
            print(f"[WARN] Error loading ember module from source: {e}")
            print(f"[WARN] Traceback: {traceback.format_exc()}")
            self._extractor = None

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """Trích xuất 2381 features từ file PE"""
        if self._extractor:
            try:
                features = self._extractor.feature_vector(bytez)
                return np.array(features, dtype=np.float32)
            except Exception as e:
                print(f"[WARN] Error using ember extractor: {e}, using fallback")
                return np.zeros(self.dim, dtype=np.float32)
        
        print(f"[WARN] ember extractor not available, returning zero vector")
        return np.zeros(self.dim, dtype=np.float32)

