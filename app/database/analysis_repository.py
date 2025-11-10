"""
Analysis Repository - CRUD operations cho analyses
"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiomysql
from app.models.analysis import Analysis, YaraMatch
from app.database.connection import get_db


class AnalysisRepository:
    """Repository cho Analysis operations"""
    
    @staticmethod
    async def create(analysis_data: Dict[str, Any]) -> Optional[int]:
        """
        Tạo analysis mới
        
        Returns:
            ID của analysis vừa tạo, hoặc None nếu lỗi
        """
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor() as cursor:
                # Insert analysis
                sql = """
                    INSERT INTO analyses (
                        filename, sha256, md5, file_size, upload_time,
                        analysis_time, malware_detected, yara_matches,
                        pe_info, suspicious_strings, capabilities
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                values = (
                    analysis_data.get('filename'),
                    analysis_data.get('sha256'),
                    analysis_data.get('md5'),
                    analysis_data.get('file_size'),
                    analysis_data.get('upload_time') or datetime.now(),
                    analysis_data.get('analysis_time', 0.0),
                    analysis_data.get('malware_detected', False),
                    json.dumps(analysis_data.get('yara_matches', [])),
                    json.dumps(analysis_data.get('pe_info')) if analysis_data.get('pe_info') else None,
                    json.dumps(analysis_data.get('suspicious_strings', [])),
                    json.dumps(analysis_data.get('capabilities', []))
                )
                
                await cursor.execute(sql, values)
                analysis_id = cursor.lastrowid
                
                # Insert YARA matches
                yara_matches = analysis_data.get('yara_matches', [])
                if yara_matches and analysis_id:
                    for match in yara_matches:
                        if isinstance(match, dict):
                            match_sql = """
                                INSERT INTO yara_matches (analysis_id, rule_name, tags, description)
                                VALUES (%s, %s, %s, %s)
                            """
                            rule_name = match.get('rule', match.get('rule_name', ''))
                            tags = ', '.join(match.get('tags', [])) if isinstance(match.get('tags'), list) else match.get('tags', '')
                            description = match.get('description', match.get('meta', {}).get('description', ''))
                            
                            await cursor.execute(match_sql, (
                                analysis_id,
                                rule_name,
                                tags,
                                description
                            ))
                
                await conn.commit()
                return analysis_id
                
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_id(analysis_id: int) -> Optional[Dict[str, Any]]:
        """Lấy analysis theo ID"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("SELECT * FROM analyses WHERE id = %s", (analysis_id,))
                row = await cursor.fetchone()
                
                if row:
                    # Parse JSON fields
                    if row.get('yara_matches'):
                        row['yara_matches'] = json.loads(row['yara_matches'])
                    if row.get('pe_info'):
                        row['pe_info'] = json.loads(row['pe_info'])
                    if row.get('suspicious_strings'):
                        row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                    if row.get('capabilities'):
                        row['capabilities'] = json.loads(row['capabilities'])
                    
                    # Get YARA matches
                    await cursor.execute("SELECT * FROM yara_matches WHERE analysis_id = %s", (analysis_id,))
                    yara_matches = await cursor.fetchall()
                    row['yara_match_details'] = yara_matches
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_all(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Lấy tất cả analyses với pagination"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return []
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("""
                    SELECT * FROM analyses 
                    ORDER BY created_at DESC 
                    LIMIT %s OFFSET %s
                """, (limit, offset))
                
                rows = await cursor.fetchall()
                
                # Parse JSON fields
                for row in rows:
                    if row.get('yara_matches'):
                        row['yara_matches'] = json.loads(row['yara_matches'])
                    if row.get('pe_info'):
                        row['pe_info'] = json.loads(row['pe_info'])
                    if row.get('suspicious_strings'):
                        row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                    if row.get('capabilities'):
                        row['capabilities'] = json.loads(row['capabilities'])
                
                return rows
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_sha256(sha256: str) -> Optional[Dict[str, Any]]:
        """Lấy analysis theo SHA256"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("""
                    SELECT * FROM analyses 
                    WHERE sha256 = %s 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """, (sha256,))
                
                row = await cursor.fetchone()
                if row:
                    # Parse JSON fields
                    if row.get('yara_matches'):
                        row['yara_matches'] = json.loads(row['yara_matches'])
                    if row.get('pe_info'):
                        row['pe_info'] = json.loads(row['pe_info'])
                    if row.get('suspicious_strings'):
                        row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                    if row.get('capabilities'):
                        row['capabilities'] = json.loads(row['capabilities'])
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_statistics() -> Dict[str, Any]:
        """Lấy thống kê"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return {
                'total_analyses': 0,
                'malware_detected': 0,
                'clean_files': 0,
                'recent_24h': 0
            }
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Total analyses
                await cursor.execute("SELECT COUNT(*) as total FROM analyses")
                total = (await cursor.fetchone())['total']
                
                # Malware detected
                await cursor.execute("SELECT COUNT(*) as count FROM analyses WHERE malware_detected = TRUE")
                malware_count = (await cursor.fetchone())['count']
                
                # Clean files
                clean_count = total - malware_count
                
                # Recent analyses (last 24h)
                await cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM analyses 
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                """)
                recent_count = (await cursor.fetchone())['count']
                
                return {
                    'total_analyses': total,
                    'malware_detected': malware_count,
                    'clean_files': clean_count,
                    'recent_24h': recent_count
                }
        finally:
            pool.release(conn)

