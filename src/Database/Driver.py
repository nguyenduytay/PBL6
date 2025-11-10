import aiomysql
import os

class Driver:
    def __init__(self):
        self.pool = None
    
    async def connect(self):
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
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None
