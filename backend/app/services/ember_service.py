"""
EMBER Service - Service for EMBER model prediction
"""
import os
import lightgbm as lgb
import numpy as np
from typing import Dict, Any, Optional
from pathlib import Path
from app.shared.ember_extractor import EmberFeatureExtractor

class EmberService:
    """Service to handle EMBER model operations"""
    
    def __init__(self):
        self.model_path = self._find_model_path()
        self.model = None
        self.extractor = EmberFeatureExtractor()
        self.threshold = 0.8336  # Standard EMBER threshold at 1% FPR
        
        self._load_model()
        
    def _find_model_path(self) -> Path:
        """Find the EMBER model file"""
        # Prioritize the user provided file
        models_dir = Path(__file__).parent.parent.parent / "models"
        
        # User specific file
        specific_model = models_dir / "20251219_002656_ember_model_pycharm.txt"
        if specific_model.exists():
            return specific_model
            
        # Fallback to standard name
        standard_model = models_dir / "ember_model_2018.txt"
        if standard_model.exists():
            return standard_model
            
        return specific_model  # Return the expected path even if missing (will fail in load)

    def _load_model(self):
        """Load LightGBM model"""
        try:
            if self.model_path.exists():
                self.model = lgb.Booster(model_file=str(self.model_path))
                print(f"[INFO] EMBER model loaded from {self.model_path}")
            else:
                print(f"[WARN] EMBER model file not found at {self.model_path}")
        except Exception as e:
            print(f"[ERROR] Failed to load EMBER model: {e}")

    def predict(self, file_path: str) -> Dict[str, Any]:
        """
        Predict if file is malicious using EMBER
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Dict containing prediction result
        """
        if not self.model:
            return {"error": "Model not loaded", "is_malware": False, "score": 0.0}
            
        try:
            with open(file_path, "rb") as f:
                bytez = f.read()
                
            features = self.extractor.feature_vector(bytez)
            # Reshape for single sample prediction
            features = features.reshape(1, -1)
            
            score = self.model.predict(features)[0]
            
            return {
                "score": float(score),
                "is_malware": score > self.threshold,
                "model_name": self.model_path.name
            }
            
        except Exception as e:
            print(f"[ERROR] EMBER prediction failed: {e}")
            return {"error": str(e), "is_malware": False, "score": 0.0}
