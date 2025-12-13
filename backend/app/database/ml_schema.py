"""
ML Schema - Database schema cho Machine Learning
Tạo các bảng để lưu features và training data
"""
import json
from typing import Dict, Any


async def create_ml_tables():
    """Tạo các bảng cho ML training"""
    from app.database.connection import _db
    
    try:
        pool = await _db.connect()
        conn = await pool.acquire()
    except Exception as e:
        print(f"[WARN] Cannot get database connection: {e}")
        return False
    
    try:
        async with conn.cursor() as cursor:
            # Bảng analysis_features - Lưu features chi tiết cho ML
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_features (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    analysis_id INT NOT NULL,
                    feature_type VARCHAR(50) NOT NULL,
                    feature_name VARCHAR(255) NOT NULL,
                    feature_value JSON,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                    INDEX idx_analysis_id (analysis_id),
                    INDEX idx_feature_type (feature_type),
                    INDEX idx_feature_name (feature_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Bảng training_data - Lưu dữ liệu đã được chuẩn bị cho training
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS training_data (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    analysis_id INT NOT NULL,
                    feature_vector JSON NOT NULL,
                    label BOOLEAN NOT NULL COMMENT 'True = malware, False = clean',
                    label_source VARCHAR(50) DEFAULT 'manual' COMMENT 'manual, yara, hash, ml',
                    confidence FLOAT DEFAULT 1.0,
                    is_verified BOOLEAN DEFAULT FALSE,
                    verified_by VARCHAR(100),
                    verified_at DATETIME NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                    INDEX idx_analysis_id (analysis_id),
                    INDEX idx_label (label),
                    INDEX idx_is_verified (is_verified),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Bảng ml_models - Lưu thông tin các ML models
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS ml_models (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    model_name VARCHAR(255) NOT NULL,
                    model_type VARCHAR(50) NOT NULL COMMENT 'random_forest, svm, neural_network, etc.',
                    model_version VARCHAR(50) NOT NULL,
                    model_path VARCHAR(500),
                    model_config JSON,
                    training_data_count INT DEFAULT 0,
                    accuracy FLOAT,
                    precision FLOAT,
                    recall FLOAT,
                    f1_score FLOAT,
                    is_active BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NULL,
                    INDEX idx_model_name (model_name),
                    INDEX idx_model_type (model_type),
                    INDEX idx_is_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Bảng model_predictions - Lưu predictions từ ML models
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS model_predictions (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    analysis_id INT NOT NULL,
                    model_id INT NOT NULL,
                    prediction BOOLEAN NOT NULL,
                    confidence FLOAT NOT NULL,
                    feature_vector JSON,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                    FOREIGN KEY (model_id) REFERENCES ml_models(id) ON DELETE CASCADE,
                    INDEX idx_analysis_id (analysis_id),
                    INDEX idx_model_id (model_id),
                    INDEX idx_prediction (prediction),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Bảng feature_statistics - Thống kê features
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS feature_statistics (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    feature_name VARCHAR(255) NOT NULL,
                    feature_type VARCHAR(50) NOT NULL,
                    total_count INT DEFAULT 0,
                    malware_count INT DEFAULT 0,
                    clean_count INT DEFAULT 0,
                    malware_ratio FLOAT DEFAULT 0.0,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_feature (feature_name, feature_type),
                    INDEX idx_feature_name (feature_name),
                    INDEX idx_malware_ratio (malware_ratio)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Bảng analysis_history - Lưu lịch sử thay đổi analysis
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    analysis_id INT NOT NULL,
                    action VARCHAR(50) NOT NULL COMMENT 'created, updated, reanalyzed, verified',
                    old_value JSON,
                    new_value JSON,
                    changed_by VARCHAR(100),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                    INDEX idx_analysis_id (analysis_id),
                    INDEX idx_action (action),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            await conn.commit()
            print("[OK] ML database tables initialized")
            return True
    except Exception as e:
        print(f"[WARN] ML database initialization error: {e}")
        return False
    finally:
        pool.release(conn)

