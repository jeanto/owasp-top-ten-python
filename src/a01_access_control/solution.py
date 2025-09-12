from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer
import sys
import os

# Adiciona o diretório shared ao path para importar módulos compartilhados
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'shared'))

from auth import build_server, get_current_user, db, User

def create_secure_app():
    """
    SOLUÇÃO PARA A01 - Broken Access Control
    
    Esta versão corrigida implementa controle de acesso adequado,
    garantindo que usuários só possam acessar seus próprios dados.
    """
    app = build_server()

    @app.get("/profile", response_model=User)
    async def get_profile_secure(
        username: str = Query(..., description="Nome do usuário"),
        current_user: dict = Depends(get_current_user)
    ):
        """
        Versão SEGURA do endpoint /profile
        
        Correções implementadas:
        1. Valida se o username solicitado corresponde ao usuário autenticado
        2. Retorna erro 403 (Forbidden) se houver tentativa de acesso não autorizado
        3. Usa apenas dados do usuário autenticado para buscar informações
        """
        
        # CORREÇÃO 1: Verifica se o usuário está tentando acessar dados de outro usuário
        authenticated_username = current_user["username"]
        if username != authenticated_username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You can only access your own profile"
            )
        
        # CORREÇÃO 2: Usa o username do usuário autenticado, não do parâmetro da query
        query = "SELECT id, username, age FROM users WHERE username = %s"
        users = db.execute_query(query, (authenticated_username,))
        
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
            "message": "OWASP A01 - Access Control SECURE Implementation",
            "security": "Users can only access their own profile data",
            "improvements": [
                "Validates user authorization before data access",
                "Returns 403 Forbidden for unauthorized access attempts",
                "Uses authenticated user data instead of query parameters"
            ]
        }
    
    return app

if __name__ == "__main__":
    import uvicorn
    secure_app = create_secure_app()
    uvicorn.run(secure_app, host="0.0.0.0", port=8002)