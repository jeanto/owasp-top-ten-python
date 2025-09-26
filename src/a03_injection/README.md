# A03 - Injection (SQL Injection)

Este laboratório demonstra vulnerabilidades de injeção SQL onde dados não validados são inseridos diretamente em consultas SQL, permitindo que atacantes executem comandos maliciosos.

## 🚨 A Vulnerabilidade

**Problema**: O sistema constrói consultas SQL concatenando strings diretamente com entrada do usuário, sem validação ou sanitização adequada.

**Exemplo de Exploração**:
```sql
-- Consulta vulnerável:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'

-- A injeção burla a autenticação porque '1'='1' é sempre verdadeiro
```

## ✅ A Correção

**Solução**: Usar consultas parametrizadas (prepared statements) que separam dados de comandos SQL:
1. Usar placeholders (?) ou parâmetros nomeados
2. Validar e sanitizar entrada do usuário
3. Implementar controles de acesso adequados
4. Usar ORMs que protegem automaticamente contra injeção

## 🔧 Pré-requisitos

### 1. Dependências Python
```bash
pip install fastapi uvicorn sqlite3 requests pytest
```

### 2. Banco de dados SQLite
Os bancos de dados SQLite são criados automaticamente quando os servidores são executados:
- `vulnerable_app.db` - Para servidor vulnerável
- `secure_app.db` - Para servidor seguro

## 🚀 Como Executar o Laboratório

### 1. Inicie o Servidor de Autenticação (Porta 8000)
```bash
cd /caminho/para/projeto
python3 src/shared/auth_server.py
```

### 2. Inicie o Servidor Vulnerável (Porta 8003)
```bash
cd src/a03_injection
python3 server.py
```
Acesse: http://localhost:8003

### 3. Inicie o Servidor Seguro (Porta 8004)
```bash
cd src/a03_injection
python3 solution.py
```
Acesse: http://localhost:8004

## 🧪 Cenários de Teste

### Cenário 1: Bypass de Autenticação via SQL Injection
**Payload**: Usuário com SQL injection para burlar login
```bash
curl -X POST http://localhost:8003/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1'\'' --", "password": "anything"}'
```
**Resultado**: Login bem-sucedido no servidor vulnerável, falha no seguro.

### Cenário 2: UNION Injection para Extrair Dados
**Payload**: Injeção UNION para revelar dados de usuários via busca de produtos
```bash
curl "http://localhost:8003/search?category=electronics'%20UNION%20SELECT%20id,%20username,%20password,%20email,%20role%20FROM%20users%20--%20"
```
**Resultado**: Dados de usuários expostos junto com produtos no servidor vulnerável.

### Cenário 3: Injeção Numérica
**Payload**: Tentativa de injeção via parâmetro numérico
```bash
curl "http://localhost:8003/users?limit=1; DROP TABLE users; --"
```
**Resultado**: Comando SQL malicioso executado no servidor vulnerável.

### Cenário 4: Consulta de Schema do Banco (Debug)
**Endpoint**: Visualizar estrutura do banco de dados
```bash
curl http://localhost:8003/debug/db-schema
```
**Resultado**: Schema do banco exposto (útil para planejar ataques).

### Cenário 5: Comparação - Funcionalidade Legítima
**Login legítimo** funcionando em ambos os servidores:
```bash
curl -X POST http://localhost:8003/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}'
```

**Busca legítima** funcionando em ambos os servidores:
```bash
curl "http://localhost:8003/search?category=electronics"
```

## 🧪 Testes Automatizados

Execute os testes unitários que validam as vulnerabilidades e correções:
```bash
cd src/a03_injection
pytest test_a03.py -v -s
```

### Testes Incluídos
- ✅ `test_vulnerable_sql_injection_login_bypass` - Confirma bypass de autenticação via SQL injection
- ✅ `test_secure_blocks_sql_injection_login` - Verifica bloqueio no servidor seguro
- ✅ `test_vulnerable_union_injection_search` - Confirma UNION injection para extrair dados
- ✅ `test_secure_blocks_union_injection_search` - Verifica proteção contra UNION injection
- ✅ `test_vulnerable_numeric_injection_users` - Testa injeção via parâmetros numéricos
- ✅ `test_secure_validates_numeric_input` - Verifica validação de entrada numérica
- ✅ `test_legitimate_login_works_on_both_servers` - Garante funcionalidade legítima
- ✅ `test_legitimate_search_works_on_both_servers` - Garante busca legítima funcional
- ✅ `test_database_schema_endpoint` - Testa endpoint de debug do schema


## 🛡️ Lições de Segurança

### O que NÃO fazer:
- ❌ Concatenar strings para formar SQL
- ❌ Confiar na validação apenas no frontend
- ❌ Usar entrada do usuário diretamente em consultas
- ❌ Expor informações de erro detalhadas

### O que fazer:
- ✅ Usar consultas parametrizadas sempre
- ✅ Validar entrada no backend
- ✅ Implementar princípio do menor privilégio
- ✅ Usar ORMs com proteção integrada
- ✅ Sanitizar saídas de erro

## 🔗 Links Úteis

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [FastAPI Security Tutorial](https://fastapi.tiangolo.com/tutorial/security/)

## 🐛 Troubleshooting

### Erro: "No such file or directory: server.py"
**Solução**: Certifique-se de estar no diretório correto (`src/a03_injection`)

### Erro: "Address already in use"
**Solução**: Pare processos nas portas 8003/8004 com `pkill -f "python.*server.py"`

### Erro: "Connection refused"
**Solução**: Aguarde alguns segundos após iniciar os servidores antes de executar testes

### Erro: "Database is locked"
**Solução**: Remova arquivos `.db` e reinicie os servidores