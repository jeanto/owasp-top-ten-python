
# A02 - Cryptographic Failure

Este laboratório demonstra falhas comuns de criptografia em aplicações web, como armazenamento inseguro de senhas e uso de algoritmos fracos.

## 🚨 A Vulnerabilidade

**Problema**: O sistema armazena senhas de usuários usando algoritmos inseguros (ex: MD5 ou texto puro), facilitando ataques de força bruta e vazamento de credenciais.

**Exemplo de Exploração**:
```bash
# Endpoint vulnerável permite alterar senha usando hash fraco
POST /change-password
{
	"username": "alice",
	"new_password": "nova_senha"
}
```

## ✅ A Correção

**Solução**: Utilizar algoritmos modernos e seguros para armazenamento de senhas, como bcrypt, sempre aplicando salt.

## 🚀 Como Executar

### Pré-requisitos
1. PostgreSQL rodando
2. Dependências instaladas: `pip install -r ../../requirements.txt`
3. Arquivo `.env` configurado (copie de `.env.example`)
4. **Crie manualmente o usuário e o banco de dados informados em `.env` no PostgreSQL:**
	 - Exemplo de comandos (no psql como superusuário):
		 ```sql
		 CREATE USER "user" WITH PASSWORD 'password';
		 CREATE DATABASE "owasp_top10_db" OWNER "user";
		 GRANT ALL PRIVILEGES ON DATABASE "owasp_top10_db" TO "user";
		 ```
	 - Substitua pelos valores reais do seu `.env`.

### Passo a Passo

#### 1. Inicie o servidor vulnerável
```bash
python server.py
```

#### 2. Inicie o servidor seguro (opcional)
```bash
python solution.py
```

#### 3. Execute os testes automatizados
```bash
pytest test_a02.py -v -s
```

### Usuários de Teste
- **alice** / senha: `alice123`
- **bob** / senha: `bob123`

### Endpoints
- `POST /change-password` - Altera a senha do usuário
- `POST /exploit-passwords` - Endpoint para explorar falhas de hash fraco

## 🧪 Testando a Vulnerabilidade

### Cenário 1: Alteração de senha insegura (MD5 ou texto puro)
```bash
curl -X POST http://localhost:8003/change-password \
	-H "Content-Type: application/json" \
	-d '{"username": "alice", "new_password": "nova_senha"}'
```
**Resultado**: Senha armazenada de forma insegura!

### Cenário 2: Visualização de todos os usuários e senhas
```bash
curl -H http://localhost:8003/all-data
```

Com o _hash_ da senha, tente encontrar a senha de Alice. Existem vários websites para decriptar _hasses_ md5.

### Cenário 3: Exploração de senhas fracas
```bash
curl -X POST http://localhost:8003/exploit-passwords \
  -H "Content-Type: application/json" \
  -d '{"password": "alice123"}'
```

Substitua "alice123" pela senha que deseja testar/explorar.

**Resultado**: Senhas podem ser recuperadas facilmente por força bruta.

### Cenário 4: Correção aplicada (bcrypt)
```bash
curl -X POST http://localhost:8004/change-password \
	-H "Content-Type: application/json" \
	-d '{"username": "alice", "new_password": "nova_senha_segura"}'
```
**Resultado**: Senha armazenada de forma segura!

## 🎭 Demonstração Automatizada

Execute os testes automatizados:
```bash
pytest test_a02.py -v -s
```

## 🛡️ Principais Lições

1. **Nunca armazene senhas em texto puro ou com hash fraco (ex: MD5)**
2. **Use algoritmos modernos como bcrypt**
3. **Sempre aplique salt nas senhas**
4. **Teste suas implementações de segurança**
5. **Proteja endpoints de alteração e recuperação de senha**

## 🔧 Troubleshooting

### Erro de Conexão com Banco
```
psycopg2.OperationalError: could not connect to server
```
**Solução**: Verifique se PostgreSQL está rodando e as credenciais no `.env`

### Servidor Não Responde
```
requests.exceptions.ConnectionError
```
**Solução**: Verifique se o servidor está rodando na porta correta
