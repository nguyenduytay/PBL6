"""
WebSocket endpoints - Cập nhật tiến trình phân tích thời gian thực
"""
import asyncio
from fastapi import APIRouter, WebSocket

router = APIRouter()

@router.websocket("/{task_id}")
async def websocket_progress(websocket: WebSocket, task_id: str):
    """
    WebSocket endpoint cập nhật tiến trình phân tích real-time
    Dùng cho dynamic analysis (sandbox) - sẽ implement sau
    """
    await websocket.accept()  # Chấp nhận kết nối WebSocket
    
    try:
        # Mô phỏng cập nhật tiến trình (0% -> 100%)
        for i in range(0, 101, 10):
            await websocket.send_json({
                "task_id": task_id,
                "progress": i,
                "status": "analyzing",
                "message": f"Processing... {i}%"
            })
            await asyncio.sleep(0.5)  # Delay 0.5s giữa các cập nhật
        
        # Gửi thông báo hoàn thành
        await websocket.send_json({
            "task_id": task_id,
            "progress": 100,
            "status": "completed",
            "message": "Analysis completed"
        })
    except Exception as e:
        # Gửi thông báo lỗi nếu có
        await websocket.send_json({
            "task_id": task_id,
            "status": "error",
            "message": str(e)
        })
    finally:
        await websocket.close()  # Đóng kết nối

