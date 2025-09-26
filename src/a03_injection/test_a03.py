import pytest
import requests
import time
import subprocess
import signal
import os
from multiprocessing import Process

import os
import sys

# Obtenha os caminhos corretos
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))

# URLs dos servidores
VULNERABLE_URL = "http://localhost:8003"
SECURE_URL = "http://localhost:8004"

class TestA03Injection:
    
    @classmethod
    def setup_class(cls):
        """Inicia ambos os servidores para teste"""
        cls.vulnerable_process = None
        cls.secure_process = None
        
        # Inicia o servidor vulnerável
        cls.vulnerable_process = subprocess.Popen([
            "python3", "server.py"
        ], cwd="src/a03_injection")
        
        # Inicia o servidor seguro
        cls.secure_process = subprocess.Popen([
            "python3", "solution.py"
        ], cwd="src/a03_injection")
        
        # Aguarda os servidores iniciarem
        time.sleep(3)
    
    @classmethod
    def teardown_class(cls):
        """Encerra ambos os servidores após os testes"""
        if cls.vulnerable_process:
            cls.vulnerable_process.terminate()
            cls.vulnerable_process.wait()
        
        if cls.secure_process:
            cls.secure_process.terminate()
            cls.secure_process.wait()
        
        # Remove arquivos de banco de dados
        for db_file in ["vulnerable_app.db", "secure_app.db"]:
            if os.path.exists(db_file):
                os.remove(db_file)

    # Testa a vulnerabilidade de injeção de SQL no
    # endpoint de login de um servidor vulnerável.
    def test_vulnerable_sql_injection_login_bypass(self):
        # Payload de SQL injection para burlar autenticação
        payload = {
            "username": "admin' OR '1'='1' --",
            "password": "anything"
        }
        
        response = requests.post(f"{VULNERABLE_URL}/login", json=payload)
        
        # Deve ser bem-sucedido devido à vulnerabilidade de SQL injection
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True
        assert "admin" in data["user"]["username"]
        
        # Verifica se a consulta vulnerável foi executada
        assert "OR '1'='1'" in data["query_executed"]

    """Testa se o servidor seguro bloqueia SQL injection no login"""
    def test_secure_blocks_sql_injection_login(self):
        # Mesmo payload de SQL injection
        payload = {
            "username": "admin' OR '1'='1' --",
            "password": "anything"
        }
        
        response = requests.post(f"{SECURE_URL}/login", json=payload)
        
        # Deve falhar - não existe usuário com esse nome exato
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    """Testa UNION SQL injection no endpoint de busca (servidor vulnerável)"""
    def test_vulnerable_union_injection_search(self):
        # Injeção UNION para extrair dados de usuários
        injection_payload = "electronics' UNION SELECT id, username, password, email, role FROM users --"
        
        response = requests.get(f"{VULNERABLE_URL}/search", params={"category": injection_payload})
        
        # Deve ser bem-sucedido e potencialmente expor dados de usuários
        assert response.status_code == 200
        data = response.json()
        
        # Verifica se a injeção foi executada
        assert "UNION SELECT" in data["query_executed"]
        
        # Verifica se recebemos dados de usuários na resposta de produtos
        products = data.get("products", [])
        # Procura por nomes de usuários no campo "name" (devido à estrutura do UNION)
        usernames_found = any("admin" in str(product.get("name", "")) for product in products)
        
        # A injeção deve revelar dados sensíveis
        assert len(products) > 0

    def test_secure_blocks_union_injection_search(self):
        """Testa se o servidor seguro bloqueia UNION injection na busca"""
        # Mesmo payload de UNION injection
        injection_payload = "electronics' UNION SELECT id, username, password, email, role FROM users --"
        
        response = requests.get(f"{SECURE_URL}/search", params={"category": injection_payload})
        
        # Deve retornar resultados normais (consulta parametrizada trata o payload como string literal)
        assert response.status_code == 200
        data = response.json()
        
        # Não deve encontrar produtos com esse nome exato de categoria
        assert len(data["products"]) == 0

    def test_vulnerable_numeric_injection_users(self):
        """Testa injeção SQL numérica no endpoint de usuários (servidor vulnerável)"""
        # Injeção em parâmetro numérico
        injection_payload = "1; DROP TABLE users; --"
        
        response = requests.get(f"{VULNERABLE_URL}/users", params={"limit": injection_payload})
        
        # Pode retornar erro devido à SQL malformada, mas a tentativa de injeção é feita
        data = response.json()
        
        # Verifica se a injeção foi tentada
        if "query_executed" in data:
            assert "DROP TABLE" in data["query_executed"]

    def test_secure_validates_numeric_input(self):
        """Testa se o servidor seguro valida entrada numérica"""
        # Entrada numérica inválida
        response = requests.get(f"{SECURE_URL}/users", params={"limit": "invalid"})
        
        # Deve retornar erro de validação
        assert response.status_code == 422  # Erro de validação do FastAPI

    def test_legitimate_login_works_on_both_servers(self):
        """Testa se login legítimo funciona em ambos os servidores"""
        legitimate_payload = {
            "username": "alice",
            "password": "alice123"
        }
        
        # Testa servidor vulnerável
        response_vuln = requests.post(f"{VULNERABLE_URL}/login", json=legitimate_payload)
        assert response_vuln.status_code == 200
        assert response_vuln.json()["user"]["username"] == "alice"
        
        # Testa servidor seguro
        response_secure = requests.post(f"{SECURE_URL}/login", json=legitimate_payload)
        assert response_secure.status_code == 200
        assert response_secure.json()["user"]["username"] == "alice"

    def test_legitimate_search_works_on_both_servers(self):
        """Testa se busca legítima funciona em ambos os servidores"""
        # Testa servidor vulnerável
        response_vuln = requests.get(f"{VULNERABLE_URL}/search", params={"category": "electronics"})
        assert response_vuln.status_code == 200
        assert len(response_vuln.json()["products"]) > 0
        
        # Testa servidor seguro
        response_secure = requests.get(f"{SECURE_URL}/search", params={"category": "electronics"})
        assert response_secure.status_code == 200
        assert len(response_secure.json()["products"]) > 0

    def test_database_schema_endpoint(self):
        """Testa o endpoint de debug do esquema do banco de dados"""
        response = requests.get(f"{VULNERABLE_URL}/debug/db-schema")
        assert response.status_code == 200
        
        schema = response.json()["schema"]
        assert "users" in schema
        assert "products" in schema
        
        # Verifica se a tabela users possui as colunas esperadas
        user_columns = [col["name"] for col in schema["users"]]
        assert "username" in user_columns
        assert "password" in user_columns
        assert "email" in user_columns

if __name__ == "__main__":
    pytest.main([__file__, "-v"])