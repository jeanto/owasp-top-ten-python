from fastapi import FastAPI
import sys
import os
from fastapi.responses import FileResponse, HTMLResponse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from routes.change_password import router as change_password_router
from routes.passwords_exploit import router as passwords_exploit_router
from auth import build_server

app = build_server()
app.include_router(change_password_router)
app.include_router(passwords_exploit_router)

# Rota para servir index.html como página principal
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index_path, media_type="text/html")

@app.get("/")
async def root():
    return {
        "mensagem": "A02 - Falha Criptográfica (Vulnerável)",
        "endpoints": ["/change-password", "/exploit-passwords"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
