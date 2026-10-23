"""Lab 8: relay opaque encrypted WebSocket messages between two room members."""
import re
from fastapi import WebSocket, WebSocketDisconnect

ROOMS = {}
ROOM_NAME = re.compile(r'[A-Za-z0-9_-]{1,32}\Z')


async def relay(websocket: WebSocket, room: str):
    if not ROOM_NAME.fullmatch(room):
        await websocket.close(code=1008)
        return
    peers = ROOMS.setdefault(room, set())
    if len(peers) >= 2:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    peers.add(websocket)
    try:
        while True:
            ciphertext = await websocket.receive_text()
            if len(ciphertext) > 8192:
                await websocket.close(code=1009)
                break
            for peer in tuple(peers):
                if peer is not websocket:
                    await peer.send_text(ciphertext)
    except WebSocketDisconnect:
        pass
    finally:
        peers.discard(websocket)
        if not peers:
            ROOMS.pop(room, None)
