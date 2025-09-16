import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

# Importa os servidores
from .server import app as vulnerable_app
from .solution import create_secure_app

# Configurações de teste
JWT_SECRET = os.getenv("JWT_SECRET", "test-secret")
JWT_ALGORITHM = "HS256"

def create_test_token(username: str) -> str:
    """Cria um token JWT válido para testes"""
    payload = {"sub": username}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def mock_db_query(username: str):
    """Mock da consulta ao banco de dados"""
    users_db = {
        "alice": {"id": 1, "username": "alice", "age": 30},
        "bob": {"id": 2, "username": "bob", "age": 25}
    }
    if username in users_db:
        return [users_db[username]]
    return []

class TestA01AccessControl:
    """
    Testes para demonstrar a vulnerabilidade A01 - Broken Access Control
    """
    
    def setup_method(self):
        """Configuração executada antes de cada teste"""
        self.vulnerable_client = TestClient(vulnerable_app)
        self.secure_client = TestClient(create_secure_app())
        
        # Tokens para diferentes usuários
        self.alice_token = create_test_token("alice")
        self.bob_token = create_test_token("bob")
        
        self.alice_headers = {"Authorization": f"Bearer {self.alice_token}"}
        self.bob_headers = {"Authorization": f"Bearer {self.bob_token}"}

    @patch('auth.db.execute_query')
    def test_vulnerable_unauthorized_access_should_fail(self, mock_db):
        print("\n > Testa se o endpoint vulnerável rejeita acessos sem autenticação | Esperado: 403 Forbidden")
        response = self.vulnerable_client.get("/profile?username=alice")
        assert response.status_code == 403  # FastAPI retorna 403 para missing bearer token

    @patch('auth.db.execute_query')  
    def test_vulnerable_allows_cross_user_access(self, mock_db):
        print("\n > Demonstra a vulnerabilidade: Alice autenticada acessa dados do Bob mudando apenas o parâmetro username | Esperado: 200 OK e dados do Bob")
        mock_db.side_effect = lambda query, params: mock_db_query(params[0])
        response = self.vulnerable_client.get(
            "/profile?username=bob", 
            headers=self.alice_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "bob"
        assert data["id"] == 2

    @patch('auth.db.execute_query')
    def test_secure_blocks_cross_user_access(self, mock_db):
        print("\n > Demonstra a correção: versão segura bloqueia acesso cross-user (Alice não acessa dados do Bob) | Esperado: 403 Forbidden e mensagem 'Access denied'")
        mock_db.side_effect = lambda query, params: mock_db_query(params[0])
        response = self.secure_client.get(
            "/profile?username=bob",
            headers=self.alice_headers
        )
        assert response.status_code == 403
        data = response.json()
        assert "Access denied" in data["detail"]

    @patch('auth.db.execute_query')
    def test_secure_allows_own_data_access(self, mock_db):
        print("\n > Testa se a versão segura permite acesso aos próprios dados | Esperado: 200 OK e dados da Alice")
        mock_db.side_effect = lambda query, params: mock_db_query(params[0])
        response = self.secure_client.get(
            "/profile?username=alice",
            headers=self.alice_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "alice"
        assert data["id"] == 1

    @patch('auth.db.execute_query')
    def test_vulnerable_user_not_found(self, mock_db):
        print("\n > Testa comportamento quando usuário não existe (versão vulnerável) | Esperado: 404 Not Found e mensagem 'User not found'")
        mock_db.return_value = []
        response = self.vulnerable_client.get(
            "/profile?username=nonexistent",
            headers=self.alice_headers
        )
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @patch('auth.db.execute_query')
    def test_secure_user_not_found(self, mock_db):
        print("\n > Testa comportamento quando usuário não existe (versão segura) | Esperado: 404 Not Found e mensagem 'User not found'")
        mock_db.return_value = []
        response = self.secure_client.get(
            "/profile?username=alice",
            headers=self.alice_headers
        )
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    def test_invalid_token_rejected(self):
        print("\n > Testa se tokens inválidos são rejeitados (vulnerável e seguro) | Esperado: 401 Unauthorized")
        invalid_headers = {"Authorization": "Bearer invalid-token"}
        response = self.vulnerable_client.get(
            "/profile?username=alice",
            headers=invalid_headers
        )
        assert response.status_code == 401
        response = self.secure_client.get(
            "/profile?username=alice", 
            headers=invalid_headers
        )
        assert response.status_code == 401

if __name__ == "__main__":
    pytest.main([__file__, "-v"])