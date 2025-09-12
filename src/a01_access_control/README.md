# A01 - Broken Access Control

Este módulo demonstra vulnerabilidades de controle de acesso onde usuários autenticados podem acessar dados de outros usuários.

## 🚨 A Vulnerabilidade

**Problema**: O endpoint `/profile` aceita um parâmetro `username` na query string e retorna dados de qualquer usuário, mesmo que o token JWT seja de outro usuário.

**Exemplo de Exploração**:
```bash
# Alice (autenticada) acessa dados do Bob
GET /profile?username=bob
Authorization: Bearer ALICE_JWT_TOKEN
```

## ✅ A Correção

**Solução**: Validar se o usuário autenticado só pode acessar seus próprios dados:

1. Extrair o username do token JWT
2. Comparar com o username solicitado
3. Retornar erro 403 se não coincidirem

## 🚀 Como Executar

### Pré-requisitos
1. PostgreSQL rodando
2. Dependências instaladas: `pip install -r ../../requirements.txt`
3. Arquivo `.env` configurado (copie de `.env.example`)

### Passo a Passo

#### 1. Configure o banco de dados
```bash
# Na raiz do projeto
python auth_helper.py setup
```

#### 2. Inicie o servidor de autenticação
```bash
# Terminal 1
python src/shared/auth_server.py
```

#### 3. Inicie o servidor vulnerável
```bash
# Terminal 2
cd src/a01_access_control
python server.py
```

#### 4. (Opcional) Inicie o servidor seguro
```bash
# Terminal 3
cd src/a01_access_control
python solution.py
```

### 🔐 Autenticação

#### Usuários de Teste
- **alice** / senha: `alice123`
- **bob** / senha: `bob123`

#### Obtendo Token JWT

**Opção 1 - Script utilitário**:
```bash
python auth_helper.py login alice alice123
```

**Opção 2 - cURL**:
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}'
```

**Opção 3 - Python**:
```python
import requests

response = requests.post("http://localhost:8000/login", json={
    "username": "alice", 
    "password": "alice123"
})

token = response.json()["access_token"]
print(f"Token: {token}")
```

## 🧪 Testando a Vulnerabilidade

### Cenário 1: Acesso Legítimo ✅
```bash
# Alice acessa seus próprios dados
curl -H "Authorization: Bearer ALICE_TOKEN" \
  "http://localhost:8001/profile?username=alice"
```

### Cenário 2: Vulnerabilidade Explorada ⚠️
```bash
# Alice acessa dados do Bob (VULNERÁVEL)
curl -H "Authorization: Bearer ALICE_TOKEN" \
  "http://localhost:8001/profile?username=bob"
```
**Resultado**: Status 200 com dados do Bob! 🚨

### Cenário 3: Correção Aplicada ✅
```bash
# Alice tenta acessar dados do Bob (SERVIDOR SEGURO)
curl -H "Authorization: Bearer ALICE_TOKEN" \
  "http://localhost:8002/profile?username=bob"
```
**Resultado**: Status 403 Forbidden ✅

## 🎭 Demonstração Automatizada

Execute a demonstração completa:
```bash
python auth_helper.py demo
```

Isso irá:
1. Configurar o banco de dados
2. Autenticar usuários
3. Demonstrar acesso legítimo
4. Explorar a vulnerabilidade
5. Mostrar a correção

## 🧪 Testes Automatizados

Execute os testes unitários:
```bash
cd src/a01_access_control
pytest test_a01.py -v
```

### Testes Incluídos
- ✅ `test_vulnerable_allows_cross_user_access` - Confirma vulnerabilidade
- ✅ `test_secure_blocks_cross_user_access` - Confirma correção
- ✅ `test_secure_allows_own_data_access` - Valida acesso próprio
- ✅ `test_invalid_token_rejected` - Testa tokens inválidos

## 📊 Exemplo de Uso com Requests

```python
import requests

# 1. Obter token
login_response = requests.post("http://localhost:8000/login", json={
    "username": "alice",
    "password": "alice123"
})
alice_token = login_response.json()["access_token"]

# 2. Headers com autenticação
headers = {"Authorization": f"Bearer {alice_token}"}

# 3. Testar vulnerabilidade
vulnerable_response = requests.get(
    "http://localhost:8001/profile?username=bob",
    headers=headers
)
print(f"Vulnerável: {vulnerable_response.status_code}")  # 200 ⚠️

# 4. Testar correção
secure_response = requests.get(
    "http://localhost:8002/profile?username=bob", 
    headers=headers
)
print(f"Seguro: {secure_response.status_code}")  # 403 ✅
```

## 🛡️ Principais Lições

1. **Nunca confie apenas na autenticação** - autorização é igualmente importante
2. **Valide permissões** antes de retornar dados sensíveis  
3. **Use dados do token JWT**, não parâmetros da requisição
4. **Implemente testes** para verificar controles de acesso
5. **Princípio do menor privilégio** - usuários só acessam o que precisam

## 🔧 Troubleshooting

### Erro de Conexão com Banco
```
psycopg2.OperationalError: could not connect to server
```
**Solução**: Verifique se PostgreSQL está rodando e as credenciais no `.env`

### Token Expirado
```
{"detail": "Token expired"}
```
**Solução**: Gere um novo token com `python auth_helper.py login alice alice123`

### Servidor Não Responde
```
requests.exceptions.ConnectionError
```
**Solução**: Verifique se o servidor está rodando na porta correta