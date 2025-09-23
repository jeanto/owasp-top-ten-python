# A03 - Injection

Este laboratório demonstra vulnerabilidades de **SQL Injection** e como preveni-las.

## 🎯 O que você aprenderá

- Como ataques de SQL Injection funcionam
- Diferentes tipos de injection (login bypass, UNION injection, numeric injection)
- Como usar consultas parametrizadas para prevenir injection
- Validação de entrada e sanitização

## 🚨 Vulnerabilidades Demonstradas

### 1. **Login Bypass via SQL Injection**
```python
# ❌ VULNERÁVEL
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

# Payload malicioso: admin' OR '1'='1' --
# Query resultante: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

### 2. **UNION Injection para Exfiltração de Dados**
```python
# ❌ VULNERÁVEL  
query += f" AND category = '{category}'"

# Payload: electronics' UNION SELECT username, password, email, role, 'injected' FROM users --
# Extrai dados sensíveis da tabela users
```

### 3. **Numeric Injection**
```python
# ❌ VULNERÁVEL
query = f"SELECT * FROM users LIMIT {limit}"

# Payload: 1; DROP TABLE users; --
# Pode executar comandos SQL adicionais
```

## ✅ Correções Implementadas

### 1. **Consultas Parametrizadas**
```python
# ✅ SEGURO
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```

### 2. **Validação de Entrada**
```python
# ✅ SEGURO
if not isinstance(limit, int) or limit < 1 or limit > 100:
    raise HTTPException(status_code=400, detail="Invalid limit parameter")
```

### 3. **Tratamento de Erros**
```python
# ✅ SEGURO - Não expor detalhes do banco
except Exception as e:
    raise HTTPException(status_code=500, detail="Database error")
```

## 🚀 Como executar

### 1. **Instalar dependências**
```bash
cd /home/jean/owasp_top10/owasp-top-ten-python
pip install -r requirements.txt
```

### 2. **Executar servidor vulnerável**
```bash
cd src/a03_injection
python server.py  # Porta 8003
```

### 3. **Executar servidor seguro**
```bash
python solution.py  # Porta 8004
```

### 4. **Executar testes**
```bash
pytest test_a03.py -v
```

## 🧪 Testes Manuais

### **Login Bypass (Vulnerável)**
```bash
# Tenta login com SQL injection
curl -X POST http://localhost:8003/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1'\'' --", "password": "anything"}'
```

### **Exfiltração de Dados (Vulnerável)**
```bash
# UNION injection para extrair dados de usuários
curl "http://localhost:8003/search?category=electronics' UNION SELECT id, username, password, email, role FROM users --"
```

### **Teste Legítimo (Ambos servidores)**
```bash
# Login normal
curl -X POST http://localhost:8003/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}'

# Busca normal
curl "http://localhost:8003/search?category=electronics"
```

### **Verificar Schema do Banco**
```bash
curl http://localhost:8003/debug/db-schema
```

## 📊 Estrutura do Banco de Dados

### **Tabela: users**
| Campo | Tipo | Descrição |
|-------|------|-----------|
| id | INTEGER | Chave primária |
| username | TEXT | Nome de usuário |
| password | TEXT | Senha (texto plano para demonstração) |
| email | TEXT | Email do usuário |
| role | TEXT | Papel do usuário (admin/user) |

### **Tabela: products**
| Campo | Tipo | Descrição |
|-------|------|-----------|
| id | INTEGER | Chave primária |
| name | TEXT | Nome do produto |
| category | TEXT | Categoria |
| price | REAL | Preço |
| description | TEXT | Descrição |

## 🎓 Dados de Teste

### **Usuários**
- `admin` / `admin123` (role: admin)
- `alice` / `alice123` (role: user)
- `bob` / `bob456` (role: user)
- `charlie` / `charlie789` (role: user)

### **Produtos**
- Laptop (electronics) - $999.99
- Phone (electronics) - $599.99
- Book (books) - $29.99
- Headphones (electronics) - $199.99
- Tablet (electronics) - $399.99

## ⚠️ Payloads de Teste

### **Login Bypass**
```
Username: admin' OR '1'='1' --
Password: qualquer_coisa
```

### **UNION Injection**
```
Category: electronics' UNION SELECT id, username, password, email, role FROM users --
```

### **Numeric Injection**
```
Limit: 1; INSERT INTO users (username, password) VALUES ('hacker', 'pwned'); --
```

## 🔍 Análise dos Resultados

### **Servidor Vulnerável (8003)**
- ✅ Aceita payloads maliciosos
- ✅ Expõe consultas SQL executadas
- ✅ Permite bypass de autenticação
- ✅ Permite exfiltração de dados

### **Servidor Seguro (8004)**
- ❌ Bloqueia tentativas de injection
- ❌ Usa consultas parametrizadas
- ❌ Valida tipos de entrada
- ❌ Não expõe detalhes internos

## 📚 Recursos Adicionais

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLite Documentation](https://sqlite.org/docs.html)
- [FastAPI Security Tutorial](https://fastapi.tiangolo.com/tutorial/security/)

## 🏆 Desafios Extras

1. **Implementar prepared statements** em diferentes cenários
2. **Criar um WAF simples** para detectar payloads de injection
3. **Implementar logging** para detectar tentativas de ataque
4. **Testar com diferentes bancos** (PostgreSQL, MySQL)
5. **Implementar rate limiting** para ataques automatizados