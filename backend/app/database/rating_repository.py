"""
Rating Repository - CRUD operations cho ratings
"""
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiomysql


class RatingRepository:
    """Repository cho Rating operations"""
    
    @staticmethod
    async def create(rating_data: Dict[str, Any]) -> Optional[int]:
        """Tạo rating mới"""
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
                    INSERT INTO ratings (
                        analysis_id, rating, comment, reviewer_name, tags, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                """
                
                values = (
                    rating_data.get('analysis_id'),
                    rating_data.get('rating'),
                    rating_data.get('comment'),
                    rating_data.get('reviewer_name'),
                    json.dumps(rating_data.get('tags', [])),
                    rating_data.get('created_at', datetime.now())
                )
                
                await cursor.execute(sql, values)
                rating_id = cursor.lastrowid
                await conn.commit()
                return rating_id
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_id(rating_id: int) -> Optional[Dict[str, Any]]:
        """Lấy rating theo ID"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("SELECT * FROM ratings WHERE id = %s", (rating_id,))
                row = await cursor.fetchone()
                
                if row and row.get('tags'):
                    row['tags'] = json.loads(row['tags'])
                
                return row
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_analysis_id(analysis_id: int, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Lấy ratings theo analysis_id"""
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
                    SELECT * FROM ratings 
                    WHERE analysis_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT %s OFFSET %s
                """, (analysis_id, limit, offset))
                
                rows = await cursor.fetchall()
                
                for row in rows:
                    if row.get('tags'):
                        row['tags'] = json.loads(row['tags'])
                
                return rows
        finally:
            pool.release(conn)
    
    @staticmethod
    async def update(rating_id: int, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Cập nhật rating"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return None
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Build update query
                set_clauses = []
                values = []
                
                if 'rating' in update_data:
                    set_clauses.append("rating = %s")
                    values.append(update_data['rating'])
                
                if 'comment' in update_data:
                    set_clauses.append("comment = %s")
                    values.append(update_data['comment'])
                
                if 'tags' in update_data:
                    set_clauses.append("tags = %s")
                    values.append(json.dumps(update_data['tags']))
                
                set_clauses.append("updated_at = %s")
                values.append(datetime.now())
                values.append(rating_id)
                
                sql = f"UPDATE ratings SET {', '.join(set_clauses)} WHERE id = %s"
                await cursor.execute(sql, values)
                await conn.commit()
                
                # Get updated rating
                return await RatingRepository.get_by_id(rating_id)
        finally:
            pool.release(conn)
    
    @staticmethod
    async def delete(rating_id: int) -> bool:
        """Xóa rating"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return False
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("DELETE FROM ratings WHERE id = %s", (rating_id,))
                await conn.commit()
                return cursor.rowcount > 0
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_statistics(analysis_id: int) -> Dict[str, Any]:
        """Lấy thống kê ratings"""
        from app.database.connection import _db
        
        try:
            pool = await _db.connect()
            conn = await pool.acquire()
        except Exception as e:
            print(f"[WARN] Cannot get database connection: {e}")
            return {
                'total_ratings': 0,
                'average_rating': 0.0,
                'rating_distribution': {1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
                'total_comments': 0,
                'common_tags': []
            }
        
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                # Total ratings
                await cursor.execute("SELECT COUNT(*) as total FROM ratings WHERE analysis_id = %s", (analysis_id,))
                total = (await cursor.fetchone())['total']
                
                # Average rating
                await cursor.execute("""
                    SELECT AVG(rating) as avg_rating 
                    FROM ratings 
                    WHERE analysis_id = %s
                """, (analysis_id,))
                avg_result = await cursor.fetchone()
                avg_rating = float(avg_result['avg_rating']) if avg_result['avg_rating'] else 0.0
                
                # Rating distribution
                await cursor.execute("""
                    SELECT rating, COUNT(*) as count 
                    FROM ratings 
                    WHERE analysis_id = %s 
                    GROUP BY rating
                """, (analysis_id,))
                distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
                for row in await cursor.fetchall():
                    distribution[row['rating']] = row['count']
                
                # Total comments
                await cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM ratings 
                    WHERE analysis_id = %s AND comment IS NOT NULL AND comment != ''
                """, (analysis_id,))
                total_comments = (await cursor.fetchone())['count']
                
                # Common tags
                await cursor.execute("""
                    SELECT tags FROM ratings 
                    WHERE analysis_id = %s AND tags IS NOT NULL
                """, (analysis_id,))
                all_tags = []
                for row in await cursor.fetchall():
                    if row['tags']:
                        tags = json.loads(row['tags'])
                        all_tags.extend(tags)
                
                # Count tags
                tag_counts = {}
                for tag in all_tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
                
                common_tags = [{"tag": tag, "count": count} for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
                
                return {
                    'total_ratings': total,
                    'average_rating': round(avg_rating, 2),
                    'rating_distribution': distribution,
                    'total_comments': total_comments,
                    'common_tags': common_tags
                }
        finally:
            pool.release(conn)

