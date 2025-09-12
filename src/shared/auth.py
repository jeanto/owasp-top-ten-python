from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
from typing import Optional

load_dotenv()

# Configurações
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

security = HTTPBearer()

class User(BaseModel):
    id: int
    username: str
    age: int

class DatabaseConnection:
    def __init__(self):
        self.connection_string = DATABASE_URL
    
    def get_connection(self):
        return psycopg2.connect(self.connection_string)
    
    def execute_query(self, query, params=None):
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        finally:
            conn.close()

db = DatabaseConnection()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Extrai e valida o token JWT, retornando os dados do usuário atual
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"username": username}
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def build_server():
    """
    Constrói e retorna a aplicação FastAPI configurada
    """
    app = FastAPI(
        title="OWASP Top 10 Workshop - Python",
        description="Workshop demonstrando vulnerabilidades de segurança",
        version="1.0.0"
    )
    
    return app