"""
Database Module - Database connection management và initialization
Module này quản lý kết nối database, connection pooling, và database initialization
"""
import os
import aiomysql
from typing import Optional
from pathlib import Path
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class Database:
    """
    Database Connection Manager - Quản lý connection pool và database operations
    
    Sử dụng aiomysql để tạo async connection pool
    """
    
    def __init__(self):
        """
        Initialize Database manager
        
        Example:
            >>> db = Database()
            >>> await db.connect()
        """
        self.pool: Optional[aiomysql.Pool] = None
    
    async def create_database_if_not_exists(self) -> bool:
        """
        Tự động tạo database nếu chưa tồn tại
        
        Returns:
            bool: True nếu tạo thành công hoặc đã tồn tại, False nếu lỗi
            
        Example:
            >>> db = Database()
            >>> success = await db.create_database_if_not_exists()
        """
        db_name = settings.DB_NAME
        
        try:
            # Kết nối vào MySQL server (không chỉ định database)
            temp_pool = await aiomysql.create_pool(
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                autocommit=True,
                minsize=1,
                maxsize=1
            )
            
            async with temp_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    # Kiểm tra database đã tồn tại chưa
                    await cursor.execute("SHOW DATABASES LIKE %s", (db_name,))
                    result = await cursor.fetchone()
                    
                    if not result:
                        # Tạo database nếu chưa tồn tại
                        await cursor.execute(
                            f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                        )
                        logger.info(f"Database '{db_name}' created successfully")
                    else:
                        logger.info(f"Database '{db_name}' already exists")
            
            temp_pool.close()
            await temp_pool.wait_closed()
            return True
            
        except Exception as e:
            logger.error(f"Cannot create database '{db_name}': {e}")
            return False
    
    async def connect(self) -> aiomysql.Pool:
        """
        Tạo connection pool để kết nối database
        
        Returns:
            aiomysql.Pool: Connection pool instance
            
        Raises:
            Exception: Nếu không thể kết nối database
            
        Example:
            >>> db = Database()
            >>> pool = await db.connect()
            >>> async with pool.acquire() as conn:
            ...     # Use connection
        """
        if not self.pool:
            self.pool = await aiomysql.create_pool(
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                host=settings.DB_HOST,
                db=settings.DB_NAME,
                port=settings.DB_PORT,
                autocommit=True,
                minsize=1,
                maxsize=5
            )
            logger.info("Database connection pool created")
        
        return self.pool
    
    async def close(self) -> None:
        """
        Đóng connection pool
        
        Example:
            >>> await db.close()
        """
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None
            logger.info("Database connection pool closed")
    
    async def get_connection(self) -> aiomysql.Connection:
        """
        Lấy connection từ pool
        
        Returns:
            aiomysql.Connection: Database connection
            
        Example:
            >>> conn = await db.get_connection()
            >>> # Use connection
            >>> pool.release(conn)
        """
        if not self.pool:
            await self.connect()
        return await self.pool.acquire()
    
    async def release_connection(self, conn: aiomysql.Connection) -> None:
        """
        Trả connection về pool
        
        Args:
            conn: Connection cần release
            
        Example:
            >>> conn = await db.get_connection()
            >>> # Use connection
            >>> await db.release_connection(conn)
        """
        if self.pool:
            self.pool.release(conn)


# Global database instance
_db = Database()


async def get_db_connection() -> aiomysql.Connection:
    """
    Dependency: Get database connection từ pool
    
    Sử dụng trong FastAPI dependencies để inject database connection
    
    Returns:
        aiomysql.Connection: Database connection
        
    Raises:
        Exception: Nếu không thể lấy connection
        
    Usage:
        @router.get("/endpoint")
        async def endpoint(conn = Depends(get_db_connection)):
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT * FROM ...")
    """
    try:
        return await _db.get_connection()
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise Exception(f"Database connection failed: {e}")


async def init_database() -> bool:
    """
    Initialize database - Tự động tạo database và tables nếu chưa có
    
    Returns:
        bool: True nếu init thành công, False nếu lỗi
        
    Example:
        >>> success = await init_database()
    """
    # Bước 1: Tạo database nếu chưa tồn tại
    db_created = await _db.create_database_if_not_exists()
    if not db_created:
        logger.warning("Cannot create database. Will try to connect anyway...")
    
    # Bước 2: Kết nối vào database
    try:
        pool = await _db.connect()
    except Exception as e:
        logger.error(f"Cannot connect to database: {e}")
        return False
    
    # Bước 3: Tạo tables nếu chưa có
    try:
        async with pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # Tạo bảng analyses
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analyses (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        filename VARCHAR(255) NOT NULL,
                        sha256 VARCHAR(64),
                        md5 VARCHAR(32),
                        file_size BIGINT,
                        upload_time DATETIME,
                        analysis_time FLOAT DEFAULT 0.0,
                        malware_detected BOOLEAN DEFAULT FALSE,
                        yara_matches JSON,
                        pe_info JSON,
                        suspicious_strings JSON,
                        capabilities JSON,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_sha256 (sha256),
                        INDEX idx_created_at (created_at),
                        INDEX idx_malware_detected (malware_detected)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                
                # Tạo bảng yara_matches
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS yara_matches (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        analysis_id INT NOT NULL,
                        rule_name VARCHAR(255) NOT NULL,
                        tags TEXT,
                        description TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                        INDEX idx_analysis_id (analysis_id),
                        INDEX idx_rule_name (rule_name)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                
                # Tạo bảng ratings
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ratings (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        analysis_id INT NOT NULL,
                        rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
                        comment TEXT,
                        reviewer_name VARCHAR(100),
                        tags JSON,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME NULL,
                        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                        INDEX idx_analysis_id (analysis_id),
                        INDEX idx_rating (rating),
                        INDEX idx_created_at (created_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                
                await conn.commit()
                logger.info("Database tables initialized")
                
                # Tạo ML tables
                from app.database.ml_schema import create_ml_tables
                await create_ml_tables()
                
                return True
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        return False

