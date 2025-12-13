"""
Training Data Repository - CRUD operations cho training data
"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiomysql


class TrainingDataRepository:
    """Repository cho Training Data operations"""
    
    @staticmethod
    async def create(training_data: Dict[str, Any]) -> Optional[int]:
        """Tạo training data mới"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor() as cursor:
                sql = """
                    INSERT INTO training_data (
                        analysis_id, feature_vector, label, label_source,
                        confidence, is_verified, verified_by, verified_at, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                values = (
                    training_data.get('analysis_id'),
                    json.dumps(training_data.get('feature_vector', {})),
                    training_data.get('label', False),
                    training_data.get('label_source', 'manual'),
                    training_data.get('confidence', 1.0),
                    training_data.get('is_verified', False),
                    training_data.get('verified_by'),
                    training_data.get('verified_at'),
                    training_data.get('created_at', datetime.now())
                )
                
                await cursor.execute(sql, values)
                training_id = cursor.lastrowid
                await conn.commit()
                return training_id
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_all(limit: int = 1000, offset: int = 0, verified_only: bool = False) -> List[Dict[str, Any]]:
        """Lấy tất cả training data"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return []
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                where_clause = "WHERE is_verified = TRUE" if verified_only else ""
                sql = f"""
                    SELECT * FROM training_data 
                    {where_clause}
                    ORDER BY created_at DESC 
                    LIMIT %s OFFSET %s
                """
                
                await cursor.execute(sql, (limit, offset))
                rows = await cursor.fetchall()
                
                for row in rows:
                    if row.get('feature_vector'):
                        row['feature_vector'] = json.loads(row['feature_vector'])
                
                return rows
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_analysis_id(analysis_id: int) -> Optional[Dict[str, Any]]:
        """Lấy training data theo analysis_id"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("SELECT * FROM training_data WHERE analysis_id = %s", (analysis_id,))
                row = await cursor.fetchone()
                
                if row and row.get('feature_vector'):
                    row['feature_vector'] = json.loads(row['feature_vector'])
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_statistics() -> Dict[str, Any]:
        """Lấy thống kê training data"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return {
                'total': 0,
                'malware': 0,
                'clean': 0,
                'verified': 0,
                'unverified': 0
            }
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Total
                await cursor.execute("SELECT COUNT(*) as total FROM training_data")
                total = (await cursor.fetchone())['total']
                
                # Malware
                await cursor.execute("SELECT COUNT(*) as count FROM training_data WHERE label = TRUE")
                malware = (await cursor.fetchone())['count']
                
                # Clean
                clean = total - malware
                
                # Verified
                await cursor.execute("SELECT COUNT(*) as count FROM training_data WHERE is_verified = TRUE")
                verified = (await cursor.fetchone())['count']
                
                # Unverified
                unverified = total - verified
                
                return {
                    'total': total,
                    'malware': malware,
                    'clean': clean,
                    'verified': verified,
                    'unverified': unverified
                }
        finally:
            pool.release(conn)
    
    @staticmethod
    async def export_for_training(format: str = 'json') -> Dict[str, Any]:
        """Export training data cho ML training"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return {'features': [], 'labels': []}
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Lấy verified data
                await cursor.execute("""
                    SELECT feature_vector, label 
                    FROM training_data 
                    WHERE is_verified = TRUE
                    ORDER BY created_at DESC
                """)
                
                rows = await cursor.fetchall()
                
                features = []
                labels = []
                
                for row in rows:
                    if row.get('feature_vector'):
                        feature_vector = json.loads(row['feature_vector'])
                        # Convert dict to list if needed
                        if isinstance(feature_vector, dict):
                            # Extract numeric values
                            feature_list = [
                                feature_vector.get('file_size', 0),
                                feature_vector.get('file_size_log', 0),
                                feature_vector.get('filename_length', 0),
                                feature_vector.get('has_extension', 0),
                                feature_vector.get('has_sha256', 0),
                                feature_vector.get('has_md5', 0),
                                feature_vector.get('yara_match_count', 0),
                                feature_vector.get('has_yara_matches', 0),
                                feature_vector.get('yara_rule_count', 0),
                                feature_vector.get('is_pe_file', 0),
                                feature_vector.get('pe_sections_count', 0),
                                feature_vector.get('pe_imports_count', 0),
                                feature_vector.get('pe_exports_count', 0),
                                feature_vector.get('pe_has_suspicious_sections', 0),
                                feature_vector.get('pe_has_packed', 0),
                                feature_vector.get('pe_has_encrypted', 0),
                                feature_vector.get('suspicious_strings_count', 0),
                                feature_vector.get('has_suspicious_strings', 0),
                                feature_vector.get('has_url_strings', 0),
                                feature_vector.get('has_ip_strings', 0),
                                feature_vector.get('has_registry_strings', 0),
                                feature_vector.get('has_crypto_strings', 0),
                                feature_vector.get('capabilities_count', 0),
                                feature_vector.get('has_network_capability', 0),
                                feature_vector.get('has_file_capability', 0),
                                feature_vector.get('has_registry_capability', 0),
                                feature_vector.get('has_process_capability', 0),
                                feature_vector.get('analysis_time', 0),
                                feature_vector.get('analysis_time_log', 0),
                            ]
                            features.append(feature_list)
                        else:
                            features.append(feature_vector)
                        
                        labels.append(1 if row['label'] else 0)
                
                return {
                    'features': features,
                    'labels': labels,
                    'count': len(features),
                    'malware_count': sum(labels),
                    'clean_count': len(labels) - sum(labels)
                }
        finally:
            pool.release(conn)

