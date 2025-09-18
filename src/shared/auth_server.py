"""
Sistema de autenticação para o OWASP Workshop Python

Este módulo fornece funcionalidades para:
- Login de usuários 
- Geração de tokens JWT
- Criação de usuários de teste
"""

import hashlib
import jwt
import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
import re

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL")

def parse_database_url(db_url):
    """
    Extrai usuário, senha, host, porta e nome do banco de uma DATABASE_URL padrão.
    Exemplo: postgresql://user:password@localhost:5432/owasp_top10_db
    """
    regex = r"postgresql://([^:]+):([^@]+)@([^:/]+):(\d+)/(\w+)"
    match = re.match(regex, db_url)
    if not match:
        raise ValueError("DATABASE_URL inválida")
    return {
        "user": match.group(1),
        "password": match.group(2),
        "host": match.group(3),
        "port": match.group(4),
        "dbname": match.group(5)
    }

def check_postgres_user_and_db():
    """
    Verifica se o usuário e banco de dados do .env existem no PostgreSQL.
    Se não existirem, exibe instruções para criação manual.
    """
    try:
        db_info = parse_database_url(DATABASE_URL)
        # Tenta conectar usando o usuário do .env
        conn_params = {
            "user": db_info["user"],
            "password": db_info["password"],
            "host": db_info["host"],
            "port": db_info["port"],
            "dbname": db_info["dbname"]
        }
        try:
            conn = psycopg2.connect(**conn_params)
            conn.close()
            print(f"✅ Usuário '{db_info['user']}' e banco '{db_info['dbname']}' existem e estão acessíveis.")
        except psycopg2.OperationalError as e:
            print(f"❌ Não foi possível conectar com o usuário/banco do .env.")
            print(f"Erro: {e}")
            print("\nPara criar manualmente:")
            print(f"1. Acesse o psql como superusuário (ex: postgres)")
            print(f"2. Execute:")
            print(f"   CREATE USER \"{db_info['user']}\" WITH PASSWORD '{db_info['password']}';")
            print(f"   CREATE DATABASE \"{db_info['dbname']}\" OWNER \"{db_info['user']}\";")
            print(f"   GRANT ALL PRIVILEGES ON DATABASE \"{db_info['dbname']}\" TO \"{db_info['user']}\";")
            print("Depois, tente rodar novamente o servidor.")
    except Exception as e:
        print(f"Erro ao verificar usuário/banco: {e}")

security = HTTPBearer()

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str

class User(BaseModel):
    id: int
    username: str
    age: int

def hash_password(password: str) -> str:
    """
    Gera hash MD5 da senha (igual ao projeto original)
    NOTA: MD5 é inseguro, usado apenas para compatibilidade com o workshop
    """
    return hashlib.md5(password.encode()).hexdigest()

def create_access_token(username: str) -> str:
    """Cria um token JWT para o usuário"""
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    """Verifica e decodifica um token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return {"username": username}
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

class Database:
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
    
    def execute_update(self, query, params=None):
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount
        finally:
            conn.close()

# Instância global do banco
db = Database()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency para extrair usuário do token JWT"""
    token = credentials.credentials
    return verify_token(token)

def authenticate_user(username: str, password: str) -> dict:
    """
    Autentica usuário verificando username e senha
    Retorna dados do usuário se autenticado, caso contrário None
    """
    password_hash = hash_password(password)
    query = "SELECT id, username, age FROM users WHERE username = %s AND password = %s"
    users = db.execute_query(query, (username, password_hash))
    
    if users:
        return users[0]
    return None

def create_test_users():
    """
    Cria usuários de teste no banco de dados
    Senhas: alice = 'alice123', bob = 'bob123'
    """
    try:
        # Verifica se a tabela users existe
        check_table = """
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = 'users'
        )
        """
        result = db.execute_query(check_table)
        
        if not result[0]['exists']:
            # Cria a tabela se não existir
            create_table = """
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(32) NOT NULL,
                age INTEGER,
                credit_card_number VARCHAR(16)
            )
            """
            db.execute_update(create_table)
            print("Tabela 'users' criada com sucesso!")
        
        # Insere usuários de teste
        alice_password = hash_password("alice123")
        bob_password = hash_password("bob123")
        
        insert_users = """
        INSERT INTO users (username, password, age, credit_card_number) 
        VALUES 
            (%s, %s, %s, %s),
            (%s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
        """
        
        db.execute_update(insert_users, (
            "alice", alice_password, 30, "1234567890123456",
            "bob", bob_password, 25, "9876543210987654"
        ))
        
        print("Usuários de teste criados:")
        print("  - alice / alice123")
        print("  - bob / bob123")
        
    except Exception as e:
        print(f"Erro ao criar usuários de teste: {e}")

def build_auth_server():
    """Cria servidor FastAPI com endpoints de autenticação"""
    app = FastAPI(
        title="Servidor de autenticação para o OWASP TOP 10",
        description="Servidor de autenticação para o OWASP TOP 10 DB"
    )
    
    @app.post("/login", response_model=LoginResponse)
    async def login(login_data: LoginRequest):
        """Endpoint para login de usuários"""
        user = authenticate_user(login_data.username, login_data.password)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        access_token = create_access_token(user["username"])
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            username=user["username"]
        )
    
    @app.get("/me", response_model=User)
    async def get_current_user_info(current_user: dict = Depends(get_current_user)):
        """Retorna informações do usuário autenticado"""
        query = "SELECT id, username, age FROM users WHERE username = %s"
        users = db.execute_query(query, (current_user["username"],))
        
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
    
    @app.post("/setup")
    async def setup_test_data():
        """Cria dados de teste (usuários alice e bob)"""
        try:
            create_test_users()
            return {"message": "Test users created successfully"}
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating test users: {str(e)}"
            )
    
    @app.get("/")
    async def root():
        return {
            "mensagem": "Servidor de autenticação para o OWASP TOP 10",
            "endpoints": {
                "/login": "POST - Login com nome de usuário/senha",
                "/me": "GET - Obter informações do usuário atual (requer autenticação)",
                "/setup": "POST - Criar usuários de teste alice e bob"
            },
            "testa_usuarios": {
                "alice": "password: alice123",
                "bob": "password: bob123"
            }
        }
    
    return app

if __name__ == "__main__":
    import uvicorn

    # Verifica usuário e banco de dados do .env
    print("\n🔧 Verificando usuário e banco de dados do .env...")
    check_postgres_user_and_db()

    # Cria usuários de teste automaticamente
    create_test_users()

    # Inicia servidor de autenticação
    app = build_auth_server()
    print("\n🚀 Servidor de autenticação iniciado em http://localhost:8000")
    print("📝 Usuários disponíveis:")
    print("   - alice / alice123")
    print("   - bob / bob123")
    print("\n💡 Para obter token:")
    print("   POST http://localhost:8000/login")
    print("   Body: {\"username\": \"alice\", \"password\": \"alice123\"}")

    uvicorn.run(app, host="0.0.0.0", port=8000)