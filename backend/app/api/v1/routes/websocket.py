"""
WebSocket - Cập nhật tiến trình thời gian thực
"""
import asyncio
from fastapi import APIRouter, WebSocket

router = APIRouter()

@router.websocket("/{task_id}")
async def websocket_progress(websocket: WebSocket, task_id: str):
    """
    WebSocket endpoint cho real-time progress updates
    Dùng cho dynamic analysis (sandbox) - sẽ implement sau
    """
    await websocket.accept()
    
    try:
        # Simulate progress updates
        for i in range(0, 101, 10):
            await websocket.send_json({
                "task_id": task_id,
                "progress": i,
                "status": "analyzing",
                "message": f"Processing... {i}%"
            })
            await asyncio.sleep(0.5)
        
        await websocket.send_json({
            "task_id": task_id,
            "progress": 100,
            "status": "completed",
            "message": "Analysis completed"
        })
    except Exception as e:
        await websocket.send_json({
            "task_id": task_id,
            "status": "error",
            "message": str(e)
        })
    finally:
        await websocket.close()

