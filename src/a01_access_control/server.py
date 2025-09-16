from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer
from fastapi.responses import FileResponse, HTMLResponse
import sys
import os
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer
import sys
import os

# Adiciona o diretório shared ao path para importar módulos compartilhados
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'shared'))

from auth import build_server, get_current_user, db, User

app = build_server()

# Rota para servir index.html como página principal
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index_path, media_type="text/html")

@app.get("/profile", response_model=User)
async def get_profile(
    username: str = Query(..., description="Nome do usuário"),
    current_user: dict = Depends(get_current_user)
):
    """
    VULNERABILIDADE A01 - Broken Access Control
    
    Este endpoint permite que um usuário autenticado acesse o perfil de qualquer
    outro usuário apenas modificando o parâmetro 'username' na query.
    
    O problema está em usar o parâmetro da query ao invés dos dados do usuário
    autenticado para buscar as informações do perfil.
    """
    # VULNERÁVEL: Usa o username da query, não do usuário autenticado
    query = "SELECT id, username, age FROM users WHERE username = %s"
    users = db.execute_query(query, (username,))
    
    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user_data = users[0]
    return User(
        id=user_data['id'],
        username=user_data['username'],
        age=user_data['age']
    )

@app.get("/")
async def root():
    return {
        "message": "OWASP A01 - Access Control Vulnerability Demo",
        "vulnerability": "Users can access other users' profiles by changing the username parameter",
        "endpoints": {
            "/profile": "GET - Requires authentication, vulnerable to access control bypass"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)