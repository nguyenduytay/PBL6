"""
Rating Service - Quản lý ratings cho analyses
"""
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.database import get_db_connection


class RatingService:
    """Service quản lý ratings"""
    
    @staticmethod
    async def create(analysis_id: int, rating: int, comment: Optional[str] = None, 
                     reviewer_name: Optional[str] = None, tags: Optional[List[str]] = None) -> int:
        """Tạo rating mới"""
        pool = await get_db_connection()
        conn = await pool.acquire()
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("""
                    INSERT INTO ratings (analysis_id, rating, comment, reviewer_name, tags, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (analysis_id, rating, comment, reviewer_name, 
                      str(tags) if tags else None, datetime.now()))
                await conn.commit()
                return cursor.lastrowid
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_by_analysis_id(analysis_id: int, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Lấy danh sách ratings của một analysis"""
        pool = await get_db_connection()
        conn = await pool.acquire()
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("""
                    SELECT id, analysis_id, rating, comment, reviewer_name, tags, 
                           created_at, updated_at
                    FROM ratings
                    WHERE analysis_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (analysis_id, limit, offset))
                
                results = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                ratings = []
                for row in results:
                    rating_dict = dict(zip(columns, row))
                    # Parse tags nếu là string
                    if rating_dict.get('tags') and isinstance(rating_dict['tags'], str):
                        try:
                            import json
                            rating_dict['tags'] = json.loads(rating_dict['tags'])
                        except:
                            rating_dict['tags'] = []
                    ratings.append(rating_dict)
                
                return ratings
        finally:
            pool.release(conn)
    
    @staticmethod
    async def get_stats(analysis_id: int) -> Dict[str, Any]:
        """Lấy thống kê ratings của một analysis"""
        pool = await get_db_connection()
        conn = await pool.acquire()
        
        try:
            async with conn.cursor() as cursor:
                # Đếm tổng số ratings và average
                await cursor.execute("""
                    SELECT COUNT(*) as total, 
                           AVG(rating) as average
                    FROM ratings
                    WHERE analysis_id = %s
                """, (analysis_id,))
                
                stats = await cursor.fetchone()
                
                if stats and stats[0]:
                    total_ratings = stats[0]
                    average_rating = float(stats[1]) if stats[1] else 0.0
                    
                    # Đếm từng rating level
                    await cursor.execute("""
                        SELECT rating, COUNT(*) as count
                        FROM ratings
                        WHERE analysis_id = %s
                        GROUP BY rating
                        ORDER BY rating
                    """, (analysis_id,))
                    
                    rating_counts = await cursor.fetchall()
                    rating_distribution = {str(rating): count for rating, count in rating_counts}
                    
                    # Đếm số comments
                    await cursor.execute("""
                        SELECT COUNT(*) as total_comments
                        FROM ratings
                        WHERE analysis_id = %s AND comment IS NOT NULL AND comment != ''
                    """, (analysis_id,))
                    
                    comments_result = await cursor.fetchone()
                    total_comments = comments_result[0] if comments_result else 0
                    
                    # Lấy common tags (simplified - chỉ đếm tags có trong ratings)
                    # Note: Tags được lưu dưới dạng JSON string, cần parse
                    await cursor.execute("""
                        SELECT tags
                        FROM ratings
                        WHERE analysis_id = %s AND tags IS NOT NULL
                    """, (analysis_id,))
                    
                    tags_results = await cursor.fetchall()
                    tag_counts = {}
                    for (tags_str,) in tags_results:
                        if tags_str:
                            try:
                                import json
                                tags = json.loads(tags_str) if isinstance(tags_str, str) else tags_str
                                if isinstance(tags, list):
                                    for tag in tags:
                                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
                            except:
                                pass
                    
                    common_tags = [{"tag": tag, "count": count} for tag, count in sorted(
                        tag_counts.items(), key=lambda x: x[1], reverse=True
                    )[:10]]  # Top 10 tags
                    
                    return {
                        "analysis_id": analysis_id,
                        "total_ratings": total_ratings,
                        "average_rating": round(average_rating, 2),
                        "rating_distribution": rating_distribution,
                        "total_comments": total_comments,
                        "common_tags": common_tags
                    }
                else:
                    return {
                        "analysis_id": analysis_id,
                        "total_ratings": 0,
                        "average_rating": 0.0,
                        "rating_distribution": {},
                        "total_comments": 0,
                        "common_tags": []
                    }
        finally:
            pool.release(conn)
    
    @staticmethod
    async def update(rating_id: int, rating: Optional[int] = None, 
                    comment: Optional[str] = None, tags: Optional[List[str]] = None) -> bool:
        """Cập nhật rating"""
        pool = await get_db_connection()
        conn = await pool.acquire()
        
        try:
            async with conn.cursor() as cursor:
                updates = []
                params = []
                
                if rating is not None:
                    updates.append("rating = %s")
                    params.append(rating)
                
                if comment is not None:
                    updates.append("comment = %s")
                    params.append(comment)
                
                if tags is not None:
                    updates.append("tags = %s")
                    params.append(str(tags))
                
                if not updates:
                    return False
                
                updates.append("updated_at = %s")
                params.append(datetime.now())
                params.append(rating_id)
                
                await cursor.execute(f"""
                    UPDATE ratings
                    SET {', '.join(updates)}
                    WHERE id = %s
                """, params)
                await conn.commit()
                
                return cursor.rowcount > 0
        finally:
            pool.release(conn)
    
    @staticmethod
    async def delete(rating_id: int) -> bool:
        """Xóa rating"""
        pool = await get_db_connection()
        conn = await pool.acquire()
        
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("DELETE FROM ratings WHERE id = %s", (rating_id,))
                await conn.commit()
                return cursor.rowcount > 0
        finally:
            pool.release(conn)

