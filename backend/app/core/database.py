"""
Database Module - Quản lý kết nối MySQL
Connection pooling với aiomysql, tự động tạo database và tables
"""
import os
import aiomysql
from typing import Optional


class Database:
    """Database connection manager"""
    
    def __init__(self):
        self.pool: Optional[aiomysql.Pool] = None
    
    async def create_database_if_not_exists(self):
        """Tự động tạo database nếu chưa tồn tại"""
        db_name = os.getenv("DB_NAME", "malwaredetection")
        
        try:
            # Kết nối vào MySQL server (không chỉ định database)
            temp_pool = await aiomysql.create_pool(
                user=os.getenv("DB_USER", "sa"),
                password=os.getenv("DB_PASSWORD", "123456"),
                host=os.getenv("DB_HOST", "127.0.0.1"),
                port=int(os.getenv("DB_PORT", "3306")),
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
                        await cursor.execute(f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                        print(f"[OK] Database '{db_name}' created successfully")
                    else:
                        print(f"[INFO] Database '{db_name}' already exists")
            
            temp_pool.close()
            await temp_pool.wait_closed()
            return True
            
        except Exception as e:
            print(f"[WARN] Cannot create database '{db_name}': {e}")
            print("[INFO] Please create database manually or check MySQL connection")
            return False
    
    async def connect(self):
        """Tạo connection pool"""
        if not self.pool:
            self.pool = await aiomysql.create_pool(
                user=os.getenv("DB_USER", "sa"),
                password=os.getenv("DB_PASSWORD", "123456"),
                host=os.getenv("DB_HOST", "127.0.0.1"),
                db=os.getenv("DB_NAME", "malwaredetection"),
                port=int(os.getenv("DB_PORT", "3306")),
                autocommit=True,
                minsize=1,
                maxsize=5
            )
        return self.pool
    
    async def close(self):
        """Đóng connection pool"""
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None
    
    async def get_connection(self):
        """Lấy connection từ pool"""
        if not self.pool:
            await self.connect()
        return await self.pool.acquire()
    
    async def release_connection(self, conn):
        """Trả connection về pool"""
        if self.pool:
            self.pool.release(conn)


# Global database instance
_db = Database()


async def get_db_connection():
    """Get database connection pool"""
    return await _db.connect()


async def init_database():
    """Initialize database - tự động tạo database và tables nếu chưa có"""
    # Bước 1: Tạo database nếu chưa tồn tại
    db_created = await _db.create_database_if_not_exists()
    if not db_created:
        print("[WARN] Cannot create database. Will try to connect anyway...")
    
    # Bước 2: Kết nối vào database
    try:
        pool = await _db.connect()
    except Exception as e:
        print(f"[WARN] Cannot connect to database: {e}")
        print("[INFO] Analysis history will not be saved. Check database configuration.")
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
                        results JSON,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_sha256 (sha256),
                        INDEX idx_created_at (created_at),
                        INDEX idx_malware_detected (malware_detected)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                
                # Thêm cột results nếu chưa có (migration)
                try:
                    await cursor.execute("ALTER TABLE analyses ADD COLUMN results JSON")
                    print("[INFO] Added 'results' column to analyses table")
                except Exception:
                    pass  # Column đã tồn tại
                
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
                print("[OK] Database tables initialized")
                
                # Tạo ML tables
                # Note: ml_schema was in old app/database folder which has been removed
                # If ML tables are needed, they should be recreated in app/services or app/core
                # try:
                #     from app.database.ml_schema import create_ml_tables
                #     await create_ml_tables()
                # except ImportError:
                #     print("[INFO] ML schema not found, skipping ML tables creation")
                
                return True
    except Exception as e:
        print(f"[WARN] Database initialization error: {e}")
        return False
