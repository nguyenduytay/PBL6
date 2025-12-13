"""
Analysis Repository Implementation - Concrete implementation của IAnalysisRepository
Repository này implement các database operations cho Analysis domain
"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiomysql
from app.domain.analyses.models import Analysis
from app.domain.analyses.repositories import IAnalysisRepository
from app.infrastructure.database import get_db_connection
from app.core.logging import get_logger

logger = get_logger(__name__)


class AnalysisRepository(IAnalysisRepository):
    """
    Analysis Repository Implementation - Implement IAnalysisRepository interface
    
    Repository này chịu trách nhiệm:
    - CRUD operations với database
    - Mapping giữa domain models và database records
    - Handle database-specific concerns (JSON parsing, etc.)
    """
    
    def __init__(self):
        """
        Initialize AnalysisRepository
        
        Example:
            >>> repo = AnalysisRepository()
        """
        pass
    
    async def create(self, analysis: Analysis) -> Optional[int]:
        """
        Tạo analysis mới trong database
        
        Args:
            analysis: Analysis domain model
            
        Returns:
            Optional[int]: ID của analysis vừa tạo, None nếu lỗi
            
        Example:
            >>> analysis = Analysis(filename="test.exe")
            >>> analysis_id = await repo.create(analysis)
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor() as cursor:
                # Insert analysis - Sử dụng parameterized query để prevent SQL injection
                sql = """
                    INSERT INTO analyses (
                        filename, sha256, md5, file_size, upload_time,
                        analysis_time, malware_detected, yara_matches,
                        pe_info, suspicious_strings, capabilities
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                values = (
                    analysis.filename,
                    analysis.sha256,
                    analysis.md5,
                    analysis.file_size,
                    analysis.upload_time or datetime.now(),
                    analysis.analysis_time,
                    analysis.malware_detected,
                    json.dumps(analysis.yara_matches),
                    json.dumps(analysis.pe_info) if analysis.pe_info else None,
                    json.dumps(analysis.suspicious_strings),
                    json.dumps(analysis.capabilities)
                )
                
                await cursor.execute(sql, values)
                analysis_id = cursor.lastrowid
                
                # Insert YARA matches vào bảng riêng
                if analysis.yara_matches and analysis_id:
                    for match in analysis.yara_matches:
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
                logger.info(f"Analysis {analysis_id} created successfully")
                return analysis_id
                
        except Exception as e:
            logger.error(f"Error creating analysis: {e}")
            await conn.rollback()
            return None
        finally:
            pool.release(conn)
    
    async def get_by_id(self, analysis_id: int) -> Optional[Analysis]:
        """
        Lấy analysis theo ID
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            Optional[Analysis]: Analysis domain model hoặc None nếu không tìm thấy
            
        Example:
            >>> analysis = await repo.get_by_id(1)
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Sử dụng parameterized query để prevent SQL injection
                await cursor.execute("SELECT * FROM analyses WHERE id = %s", (analysis_id,))
                row = await cursor.fetchone()
                
                if not row:
                    return None
                
                # Parse JSON fields
                if row.get('yara_matches'):
                    row['yara_matches'] = json.loads(row['yara_matches'])
                if row.get('pe_info'):
                    row['pe_info'] = json.loads(row['pe_info'])
                if row.get('suspicious_strings'):
                    row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                if row.get('capabilities'):
                    row['capabilities'] = json.loads(row['capabilities'])
                
                # Convert database row thành Analysis domain model
                return self._row_to_analysis(row)
                
        except Exception as e:
            logger.error(f"Error getting analysis {analysis_id}: {e}")
            return None
        finally:
            pool.release(conn)
    
    async def get_all(self, limit: int = 100, offset: int = 0) -> List[Analysis]:
        """
        Lấy danh sách analyses với pagination
        
        Args:
            limit: Số lượng kết quả tối đa
            offset: Vị trí bắt đầu
            
        Returns:
            List[Analysis]: Danh sách analyses
            
        Example:
            >>> analyses = await repo.get_all(limit=20, offset=0)
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return []
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Sử dụng parameterized query
                await cursor.execute("""
                    SELECT * FROM analyses 
                    ORDER BY created_at DESC 
                    LIMIT %s OFFSET %s
                """, (limit, offset))
                
                rows = await cursor.fetchall()
                
                # Parse JSON fields và convert sang domain models
                analyses = []
                for row in rows:
                    if row.get('yara_matches'):
                        row['yara_matches'] = json.loads(row['yara_matches'])
                    if row.get('pe_info'):
                        row['pe_info'] = json.loads(row['pe_info'])
                    if row.get('suspicious_strings'):
                        row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                    if row.get('capabilities'):
                        row['capabilities'] = json.loads(row['capabilities'])
                    
                    analyses.append(self._row_to_analysis(row))
                
                return analyses
                
        except Exception as e:
            logger.error(f"Error getting analyses: {e}")
            return []
        finally:
            pool.release(conn)
    
    async def get_by_sha256(self, sha256: str) -> Optional[Analysis]:
        """
        Lấy analysis theo SHA256 hash
        
        Args:
            sha256: SHA256 hash string
            
        Returns:
            Optional[Analysis]: Analysis domain model hoặc None nếu không tìm thấy
            
        Example:
            >>> analysis = await repo.get_by_sha256("abc123...")
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Sử dụng parameterized query
                await cursor.execute("SELECT * FROM analyses WHERE sha256 = %s", (sha256,))
                row = await cursor.fetchone()
                
                if not row:
                    return None
                
                # Parse JSON fields
                if row.get('yara_matches'):
                    row['yara_matches'] = json.loads(row['yara_matches'])
                if row.get('pe_info'):
                    row['pe_info'] = json.loads(row['pe_info'])
                if row.get('suspicious_strings'):
                    row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                if row.get('capabilities'):
                    row['capabilities'] = json.loads(row['capabilities'])
                
                return self._row_to_analysis(row)
                
        except Exception as e:
            logger.error(f"Error getting analysis by SHA256: {e}")
            return None
        finally:
            pool.release(conn)
    
    async def search(self, query: str, limit: int = 50, offset: int = 0) -> List[Analysis]:
        """
        Tìm kiếm analyses theo filename, SHA256, hoặc MD5
        
        Args:
            query: Từ khóa tìm kiếm
            limit: Số lượng kết quả tối đa
            offset: Vị trí bắt đầu
            
        Returns:
            List[Analysis]: Danh sách analyses khớp với query
            
        Example:
            >>> results = await repo.search("test.exe", limit=10)
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return []
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Sử dụng LIKE với parameterized query để prevent SQL injection
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
                
                # Parse JSON fields và convert sang domain models
                analyses = []
                for row in rows:
                    if row.get('yara_matches'):
                        row['yara_matches'] = json.loads(row['yara_matches'])
                    if row.get('pe_info'):
                        row['pe_info'] = json.loads(row['pe_info'])
                    if row.get('suspicious_strings'):
                        row['suspicious_strings'] = json.loads(row['suspicious_strings'])
                    if row.get('capabilities'):
                        row['capabilities'] = json.loads(row['capabilities'])
                    
                    analyses.append(self._row_to_analysis(row))
                
                return analyses
                
        except Exception as e:
            logger.error(f"Error searching analyses: {e}")
            return []
        finally:
            pool.release(conn)
    
    async def count_all(self) -> int:
        """
        Đếm tổng số analyses trong database
        
        Returns:
            int: Tổng số analyses
            
        Example:
            >>> total = await repo.count_all()
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return 0
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT COUNT(*) FROM analyses")
                total = (await cursor.fetchone())[0]
                return total
        except Exception as e:
            logger.error(f"Error counting analyses: {e}")
            return 0
        finally:
            pool.release(conn)
    
    async def count_search(self, query: str) -> int:
        """
        Đếm tổng số kết quả search
        
        Args:
            query: Từ khóa tìm kiếm
            
        Returns:
            int: Tổng số kết quả
            
        Example:
            >>> count = await repo.count_search("test")
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
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
        except Exception as e:
            logger.error(f"Error counting search results: {e}")
            return 0
        finally:
            pool.release(conn)
    
    async def delete(self, analysis_id: int) -> bool:
        """
        Xóa analysis theo ID (CASCADE sẽ xóa YARA matches và ratings)
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            bool: True nếu xóa thành công, False nếu không
            
        Example:
            >>> success = await repo.delete(1)
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return False
        
        try:
            async with conn.cursor() as cursor:
                # Sử dụng parameterized query
                await cursor.execute("DELETE FROM analyses WHERE id = %s", (analysis_id,))
                await conn.commit()
                
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info(f"Analysis {analysis_id} deleted successfully")
                
                return deleted
                
        except Exception as e:
            logger.error(f"Error deleting analysis {analysis_id}: {e}")
            await conn.rollback()
            return False
        finally:
            pool.release(conn)
    
    async def update(self, analysis_id: int, analysis_data: Dict[str, Any]) -> bool:
        """
        Update analysis
        
        Args:
            analysis_id: Analysis ID
            analysis_data: Dictionary chứa data cần update
            
        Returns:
            bool: True nếu update thành công, False nếu không
            
        Example:
            >>> success = await repo.update(1, {"malware_detected": True})
        """
        from app.infrastructure.database import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            logger.error(f"Cannot get database connection: {e}")
            return False
        
        try:
            async with conn.cursor() as cursor:
                # Build dynamic UPDATE query dựa trên fields có trong analysis_data
                set_clauses = []
                values = []
                
                for key, value in analysis_data.items():
                    if key in ['yara_matches', 'pe_info', 'suspicious_strings', 'capabilities']:
                        # JSON fields cần serialize
                        set_clauses.append(f"{key} = %s")
                        values.append(json.dumps(value) if value else None)
                    else:
                        set_clauses.append(f"{key} = %s")
                        values.append(value)
                
                if not set_clauses:
                    return False
                
                values.append(analysis_id)
                sql = f"UPDATE analyses SET {', '.join(set_clauses)} WHERE id = %s"
                
                await cursor.execute(sql, values)
                await conn.commit()
                
                updated = cursor.rowcount > 0
                if updated:
                    logger.info(f"Analysis {analysis_id} updated successfully")
                
                return updated
                
        except Exception as e:
            logger.error(f"Error updating analysis {analysis_id}: {e}")
            await conn.rollback()
            return False
        finally:
            pool.release(conn)
    
    def _row_to_analysis(self, row: Dict[str, Any]) -> Analysis:
        """
        Convert database row thành Analysis domain model
        
        Args:
            row: Database row dictionary
            
        Returns:
            Analysis: Analysis domain model
            
        Example:
            >>> analysis = repo._row_to_analysis(row)
        """
        return Analysis(
            id=row.get('id'),
            filename=row.get('filename', ''),
            sha256=row.get('sha256'),
            md5=row.get('md5'),
            file_size=row.get('file_size'),
            upload_time=row.get('upload_time'),
            analysis_time=row.get('analysis_time', 0.0),
            malware_detected=bool(row.get('malware_detected', False)),
            yara_matches=row.get('yara_matches', []),
            pe_info=row.get('pe_info'),
            suspicious_strings=row.get('suspicious_strings', []),
            capabilities=row.get('capabilities', []),
            created_at=row.get('created_at')
        )

