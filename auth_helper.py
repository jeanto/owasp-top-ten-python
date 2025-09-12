#!/usr/bin/env python3
"""
Script utilitário para autenticação no OWASP Workshop

Este script facilita:
- Obtenção de tokens JWT
- Teste de endpoints autenticados
- Setup inicial do banco de dados
"""

import requests
import json
import sys
import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://localhost:8000"
PROFILE_URL_VULNERABLE = "http://localhost:8001"
PROFILE_URL_SECURE = "http://localhost:8002"

def get_token(username: str, password: str) -> str:
    """Obtém token JWT para um usuário"""
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            return data["access_token"]
        else:
            print(f"❌ Erro no login: {response.status_code}")
            print(f"   {response.json().get('detail', 'Erro desconhecido')}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro: Servidor de autenticação não está rodando!")
        print("   Execute: python src/shared/auth_server.py")
        return None

def test_profile_access(token: str, username: str, server_type: str = "vulnerable"):
    """Testa acesso ao endpoint de perfil"""
    url = PROFILE_URL_VULNERABLE if server_type == "vulnerable" else PROFILE_URL_SECURE
    
    try:
        response = requests.get(
            f"{url}/profile",
            params={"username": username},
            headers={"Authorization": f"Bearer {token}"}
        )
        
        print(f"🔍 Testando acesso ao perfil de '{username}' no servidor {server_type}")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Sucesso! Dados: {data}")
        else:
            print(f"   ❌ Falha: {response.json().get('detail', 'Erro desconhecido')}")
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Erro: Servidor {server_type} não está rodando!")
        port = "8001" if server_type == "vulnerable" else "8002"
        print(f"   Execute: python src/a01_access_control/{'server.py' if server_type == 'vulnerable' else 'solution.py'}")

def setup_database():
    """Configura banco de dados com usuários de teste"""
    try:
        response = requests.post(f"{BASE_URL}/setup")
        if response.status_code == 200:
            print("✅ Banco de dados configurado com sucesso!")
            print("   Usuários criados: alice, bob")
        else:
            print("❌ Erro ao configurar banco de dados")
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro: Servidor de autenticação não está rodando!")

def main():
    if len(sys.argv) < 2:
        print("🔐 OWASP Workshop - Utilitário de Autenticação")
        print()
        print("Uso:")
        print("  python auth_helper.py setup                    # Configura banco de dados")
        print("  python auth_helper.py login <user> <pass>      # Obtém token")
        print("  python auth_helper.py test <token> <user>      # Testa acesso vulnerável")
        print("  python auth_helper.py test-secure <token> <user> # Testa acesso seguro")
        print("  python auth_helper.py demo                     # Demonstração completa")
        print()
        print("Usuários de teste:")
        print("  - alice / alice123")
        print("  - bob / bob123")
        return
    
    command = sys.argv[1]
    
    if command == "setup":
        setup_database()
        
    elif command == "login":
        if len(sys.argv) != 4:
            print("Uso: python auth_helper.py login <username> <password>")
            return
        
        username, password = sys.argv[2], sys.argv[3]
        token = get_token(username, password)
        
        if token:
            print(f"✅ Token obtido para {username}:")
            print(f"   {token}")
            print()
            print("💡 Use este token nos headers HTTP:")
            print(f"   Authorization: Bearer {token}")
    
    elif command == "test":
        if len(sys.argv) != 4:
            print("Uso: python auth_helper.py test <token> <username>")
            return
        
        token, username = sys.argv[2], sys.argv[3]
        test_profile_access(token, username, "vulnerable")
    
    elif command == "test-secure":
        if len(sys.argv) != 4:
            print("Uso: python auth_helper.py test-secure <token> <username>")
            return
        
        token, username = sys.argv[2], sys.argv[3]
        test_profile_access(token, username, "secure")
    
    elif command == "demo":
        print("🎭 DEMONSTRAÇÃO COMPLETA DA VULNERABILIDADE A01")
        print("=" * 50)
        
        # 1. Configura banco
        print("\n1️⃣ Configurando banco de dados...")
        setup_database()
        
        # 2. Obtém tokens
        print("\n2️⃣ Obtendo tokens de autenticação...")
        alice_token = get_token("alice", "alice123")
        bob_token = get_token("bob", "bob123")
        
        if not alice_token or not bob_token:
            print("❌ Falha na autenticação. Verifique se o servidor está rodando.")
            return
        
        print(f"   Alice token: {alice_token[:20]}...")
        print(f"   Bob token: {bob_token[:20]}...")
        
        # 3. Testa acesso legítimo
        print("\n3️⃣ Testando acesso legítimo (Alice -> dados Alice)...")
        test_profile_access(alice_token, "alice", "vulnerable")
        
        # 4. Demonstra vulnerabilidade
        print("\n4️⃣ DEMONSTRANDO VULNERABILIDADE (Alice -> dados Bob)...")
        test_profile_access(alice_token, "bob", "vulnerable")
        
        # 5. Testa correção
        print("\n5️⃣ Testando correção no servidor seguro...")
        test_profile_access(alice_token, "bob", "secure")
        
        print("\n🎯 DEMONSTRAÇÃO CONCLUÍDA!")
        print("   - Servidor vulnerável permite acesso cross-user")
        print("   - Servidor seguro bloqueia acesso não autorizado")
    
    else:
        print(f"❌ Comando desconhecido: {command}")

if __name__ == "__main__":
    main()