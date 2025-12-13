"""
ML Service - Service để train và predict với ML models
"""
import json
import pickle
from typing import Dict, Any, List, Optional
from pathlib import Path
from fastapi import HTTPException


class MLService:
    """Service cho Machine Learning operations"""
    
    def __init__(self):
        self.models_path = Path(__file__).parent.parent.parent / "models"
        self.models_path.mkdir(exist_ok=True)
    
    async def train_model(
        self,
        model_type: str,
        features: List[List[float]],
        labels: List[int],
        model_name: str = None
    ) -> Dict[str, Any]:
        """
        Train ML model
        
        Args:
            model_type: Loại model ('random_forest', 'svm', 'neural_network')
            features: Feature vectors
            labels: Labels (0 = clean, 1 = malware)
            model_name: Tên model
            
        Returns:
            Dict chứa model info và metrics
        """
        try:
            if model_type == 'random_forest':
                from sklearn.ensemble import RandomForestClassifier
                from sklearn.model_selection import train_test_split
                from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
                
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    features, labels, test_size=0.2, random_state=42
                )
                
                # Train model
                model = RandomForestClassifier(n_estimators=100, random_state=42)
                model.fit(X_train, y_train)
                
                # Evaluate
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred)
                recall = recall_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred)
                
                # Save model
                model_name = model_name or f"rf_model_{len(features)}"
                model_path = self.models_path / f"{model_name}.pkl"
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
                
                return {
                    'model_name': model_name,
                    'model_type': model_type,
                    'model_path': str(model_path),
                    'accuracy': float(accuracy),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1),
                    'training_samples': len(X_train),
                    'test_samples': len(X_test)
                }
            
            elif model_type == 'svm':
                from sklearn.svm import SVC
                from sklearn.model_selection import train_test_split
                from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
                
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    features, labels, test_size=0.2, random_state=42
                )
                
                # Train model
                model = SVC(kernel='rbf', probability=True, random_state=42)
                model.fit(X_train, y_train)
                
                # Evaluate
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred)
                recall = recall_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred)
                
                # Save model
                model_name = model_name or f"svm_model_{len(features)}"
                model_path = self.models_path / f"{model_name}.pkl"
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
                
                return {
                    'model_name': model_name,
                    'model_type': model_type,
                    'model_path': str(model_path),
                    'accuracy': float(accuracy),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1),
                    'training_samples': len(X_train),
                    'test_samples': len(X_test)
                }
            
            else:
                raise ValueError(f"Unsupported model type: {model_type}")
                
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="scikit-learn not installed. Install with: pip install scikit-learn"
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error training model: {str(e)}")
    
    def predict(self, model_path: str, feature_vector: List[float]) -> Dict[str, Any]:
        """
        Predict với model
        
        Args:
            model_path: Đường dẫn đến model file
            feature_vector: Feature vector của file cần predict
            
        Returns:
            Dict chứa prediction và confidence
        """
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            # Predict
            prediction = model.predict([feature_vector])[0]
            probabilities = model.predict_proba([feature_vector])[0] if hasattr(model, 'predict_proba') else None
            
            confidence = float(probabilities[prediction]) if probabilities is not None else 1.0
            
            return {
                'prediction': bool(prediction),
                'confidence': confidence,
                'probabilities': {
                    'clean': float(probabilities[0]) if probabilities else 0.0,
                    'malware': float(probabilities[1]) if probabilities else 0.0
                } if probabilities else None
            }
            
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Model file not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error predicting: {str(e)}")

