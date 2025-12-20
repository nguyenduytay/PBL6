"""
Analysis Service - CRUD operations cho analyses
Quản lý lưu trữ, tìm kiếm, thống kê các kết quả phân tích malware
"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiomysql  # type: ignore[import-untyped]


class AnalysisService:
    """Service cho Analysis operations - Kết hợp business logic và data access"""
    
    @staticmethod
    async def create(analysis_data: Dict[str, Any]) -> Optional[int]:
        """
        Tạo analysis mới
        
        Args:
            analysis_data: Dictionary chứa thông tin analysis
            
        Returns:
            ID của analysis vừa tạo, hoặc None nếu lỗi
        """
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
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
                        pe_info, suspicious_strings, capabilities, results
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    json.dumps(analysis_data.get('capabilities', [])),
                    json.dumps(analysis_data.get('results', []))
                )
                
                await cursor.execute(sql, values)
                analysis_id = cursor.lastrowid
                
                # Insert YARA matches
                import json
                yara_matches = analysis_data.get('yara_matches', [])
                if yara_matches and analysis_id:
                    for match in yara_matches:
                        if isinstance(match, dict):
                            match_sql = """
                                INSERT INTO yara_matches (analysis_id, rule_name, tags, description, author, reference, matched_strings)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """
                            rule_name = match.get('rule', match.get('rule_name', ''))
                            tags = ', '.join(match.get('tags', [])) if isinstance(match.get('tags'), list) else match.get('tags', '')
                            description = match.get('description', match.get('meta', {}).get('description', ''))
                            author = match.get('author', match.get('meta', {}).get('author', ''))
                            reference = match.get('reference', match.get('meta', {}).get('reference', ''))
                            matched_strings = json.dumps(match.get('matched_strings', [])) if match.get('matched_strings') else None
                            
                            await cursor.execute(match_sql, (
                                analysis_id,
                                rule_name,
                                tags,
                                description,
                                author,
                                reference,
                                matched_strings
                            ))
                
                await conn.commit()
                return analysis_id
                
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_id(analysis_id: int) -> Optional[Dict[str, Any]]:
        """Lấy analysis theo ID"""
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
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
                    if row.get('results'):
                        row['results'] = json.loads(row['results'])
                    else:
                        row['results'] = []
                    
                    # Get YARA matches với matched strings
                    await cursor.execute("SELECT * FROM yara_matches WHERE analysis_id = %s", (analysis_id,))
                    yara_matches = await cursor.fetchall()
                    # Parse matched_strings JSON
                    for match in yara_matches:
                        if match.get('matched_strings'):
                            try:
                                match['matched_strings'] = json.loads(match['matched_strings'])
                            except:
                                match['matched_strings'] = []
                        # Parse tags nếu là string
                        if match.get('tags') and isinstance(match['tags'], str):
                            match['tags'] = [t.strip() for t in match['tags'].split(',') if t.strip()]
                    row['yara_matches'] = yara_matches
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_all(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Lấy tất cả analyses với pagination"""
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
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
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
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
                    if row.get('results'):
                        row['results'] = json.loads(row['results'])
                    else:
                        row['results'] = []
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def search(query: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Search analyses by filename, SHA256, or MD5
        
        Args:
            query: Search keyword
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List of matching analyses
        """
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return []
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Search in filename, SHA256, and MD5 using LIKE
                search_pattern = f"%{query}%"
                await cursor.execute("""
                    SELECT * FROM analyses 
                    WHERE filename LIKE %s 
                       OR sha256 LIKE %s 
                       OR md5 LIKE %s
                    ORDER BY created_at DESC 
                    LIMIT %s OFFSET %s
                """, (search_pattern, search_pattern, search_pattern, limit, offset))
                
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
    async def count_search(query: str) -> int:
        """
        Count total search results by filename, SHA256, or MD5
        
        Args:
            query: Search keyword
            
        Returns:
            Total count of matching analyses
        """
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return 0
        
        try:
            async with conn.cursor() as cursor:
                search_pattern = f"%{query}%"
                await cursor.execute("""
                    SELECT COUNT(*) FROM analyses 
                    WHERE filename LIKE %s 
                       OR sha256 LIKE %s 
                       OR md5 LIKE %s
                """, (search_pattern, search_pattern, search_pattern))
                
                total = (await cursor.fetchone())[0]
                return total
        finally:
            pool.release(conn)
    
    @staticmethod
    async def count_all() -> int:
        """Đếm tổng số analyses"""
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return 0
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT COUNT(*) as total FROM analyses")
                result = await cursor.fetchone()
                return result[0] if result else 0
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_statistics() -> Dict[str, Any]:
        """Lấy thống kê"""
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
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
    
    @staticmethod
    async def delete(analysis_id: int) -> bool:
        """Xóa analysis và các dữ liệu liên quan"""
        from app.core.database import get_db_connection
        
        try:
            pool = await get_db_connection()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return False
        
        try:
            async with conn.cursor() as cursor:
                # Xóa YARA matches trước (foreign key constraint)
                await cursor.execute("DELETE FROM yara_matches WHERE analysis_id = %s", (analysis_id,))
                
                # Xóa ratings liên quan
                await cursor.execute("DELETE FROM ratings WHERE analysis_id = %s", (analysis_id,))
                
                # Xóa analysis
                await cursor.execute("DELETE FROM analyses WHERE id = %s", (analysis_id,))
                await conn.commit()
                
                return cursor.rowcount > 0
        finally:
            pool.release(conn)
