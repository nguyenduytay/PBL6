"""
Predictor - Wrapper cho prediction logic
Tổng hợp các ML models để dự đoán malware
"""
from typing import Dict, Any
from app.ml.ember_model import EmberModel

class Predictor:
    """Wrapper xử lý prediction logic cho các models"""
    
    def __init__(self):
        self.ember_model = EmberModel()
    
    def predict_ember(self, file_path: str) -> Dict[str, Any]:
        """
        Dự đoán bằng EMBER model
        
        Args:
            file_path: Đường dẫn đến file PE
            
        Returns:
            Dict chứa kết quả dự đoán
        """
        return self.ember_model.predict(file_path)
    
    def is_ember_loaded(self) -> bool:
        """Kiểm tra EMBER model đã load chưa"""
        return self.ember_model.is_model_loaded()

