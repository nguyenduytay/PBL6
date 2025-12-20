"""
EMBER Model - Wrapper cho EMBER LightGBM model
Load và sử dụng EMBER model để dự đoán malware từ PE files
"""
import os
import lightgbm as lgb
import numpy as np
from typing import Dict, Any, Optional
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
            print(f"[ERROR] Failed to load EMBER model: {e}")
            print(f"[ERROR] Model path: {self.model_path}")
            self.model = None
    
    def is_model_loaded(self) -> bool:
        """Kiểm tra model đã được load thành công chưa"""
        return self.model is not None

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
            
        try:
            # Đọc file dưới dạng bytes
            with open(file_path, "rb") as f:
                bytez = f.read()
            
            # Trích xuất features từ file PE (2381 features)
            features = self.extractor.feature_vector(bytez)
            
            # Reshape để predict (1 sample, n features)
            features = features.reshape(1, -1)
            
            # Dự đoán bằng model
            score = self.model.predict(features)[0]
            
            return {
                "score": float(score),
                "is_malware": score > self.threshold,
                "model_name": self.model_filename,
                "threshold": self.threshold
            }
            
        except Exception as e:
            print(f"[ERROR] EMBER prediction failed for {file_path}: {e}")
            import traceback
            traceback.print_exc()
            return {
                "error": str(e), 
                "is_malware": False, 
                "score": 0.0,
                "model_name": self.model_filename
            }

