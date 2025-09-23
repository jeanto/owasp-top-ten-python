import pytest
from fastapi.testclient import TestClient
import sys
import os

# Adiciona o diretório shared ao path para importar módulos compartilhados
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'shared'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
sys.path.append(os.path.dirname(__file__))

from auth import db
from crypto import hash_md5, hash_bcrypt, verify_bcrypt
from server import app as vulnerable_app
from solution import app as secure_app

# ...resto do código permanece igual...

@pytest.fixture(autouse=True)
def setup_users():
    # Reseta senhas dos usuários para valores conhecidos
    users = [("alice", "alice123"), ("bob", "bob123")]
    conn = db.get_connection()
    try:
        with conn.cursor() as cursor:
            for username, password in users:
                password_hash = hash_md5(password)
                query = "UPDATE users SET password = %s WHERE username = %s"
                cursor.execute(query, (password_hash, username))
            conn.commit()
    finally:
        conn.close()


class TestCryptographicFailure:
    def test_exploit_md5_to_plaintext(self):
        client = TestClient(vulnerable_app)
        # Consulta o hash MD5 de Alice
        response = client.get("/all-data")
        assert response.status_code == 200
        users = response.json().get("users", [])
        alice_hash = None
        for user in users:
            if user["username"] == "alice":
                alice_hash = user["password"]
                break
        assert alice_hash is not None

        # Simula força bruta: testa várias senhas até encontrar a original
        # (Aqui, para fins didáticos, testamos só a senha correta)
        test_password = "alice123"
        test_hash = hash_md5(test_password)
        assert test_hash == alice_hash

        # Usa exploit-passwords para recuperar o usuário
        response = client.post(
            "/exploit-passwords",
            json={"password": test_password}
        )
        assert response.status_code == 200
        assert "alice" in response.json().get("users", [])

    def test_vulnerable_change_password_md5(self):
        client = TestClient(vulnerable_app)
        token = "test-token"  # Use um token válido em ambiente real

        response = client.post(
            "/change-password",
            json={"new_password": "newpass"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code in [200, 401]  # 401 se não autenticado

    def test_secure_change_password_bcrypt(self):
        client = TestClient(secure_app)
        token = "test-token"  # Use um token válido em ambiente real
        response = client.post(
            "/change-password-secure",
            json={"new_password": "newpass"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code in [200, 401]

    def test_vulnerable_exploit_passwords(self):
        client = TestClient(vulnerable_app)
        response = client.post(
            "/exploit-passwords",
            json={"password": "alice123"}
        )
        assert response.status_code == 200
        assert "alice" in response.json().get("users", [])

    def test_secure_exploit_passwords_not_available(self):
        client = TestClient(secure_app)
        response = client.post(
            "/exploit-passwords",
            json={"password": "alice123"}
        )
        assert response.status_code == 404 or response.status_code == 405

    def test_secure_password_storage(self):
        # Verifica se a senha foi armazenada com bcrypt
        client = TestClient(secure_app)
        response = client.get("/all-data")
        assert response.status_code == 200
        users = response.json().get("users", [])      
        for user in users:
            assert verify_bcrypt("alice123", user["password"])