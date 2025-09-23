from fastapi import FastAPI
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from routes.change_password_secure import router as change_password_router
from routes.passwords_exploit import router as passwords_exploit_router

from auth import build_server

app = build_server()
app.include_router(change_password_router)
app.include_router(passwords_exploit_router)

@app.get("/")
async def root():
    return {
        "mensagem": "A02 - Falha Criptográfica (Segura)",
        "endpoints": ["/change-password-secure", "/exploit-passwords"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
