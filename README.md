# OWASP Top 10 Workshop - Python Edition

Workshop prático para demonstrar as principais vulnerabilidades de segurança em aplicações web segundo o OWASP Top 10, implementado em Python com FastAPI.

## Estrutura do Projeto

Este projeto é equivalente ao workshop original em JavaScript/Node.js, mas implementado usando Python e FastAPI.

### A01 - Broken Access Control

Demonstra vulnerabilidades de controle de acesso onde usuários autenticados podem acessar dados de outros usuários.

## Setup do Ambiente

### Pré-requisitos
- Python 3.8+
- PostgreSQL
- pip

### Instalação

1. Clone o repositório
2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Configure as variáveis de ambiente criando um arquivo `.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/owasp_workshop
JWT_SECRET=your-secret-key-here
```

4. Execute as migrações do banco de dados (use as mesmas do projeto original)

## Como executar

### A01 - Access Control

```bash
cd src/a01_access_control
python server.py
```

Para executar os testes:
```bash
cd src/a01_access_control
pytest test_a01.py -v
```

## Vulnerabilidades Demonstradas

### A01 - Broken Access Control
- **Problema**: Usuário autenticado pode acessar perfis de outros usuários modificando o parâmetro `username`
- **Impacto**: Vazamento de dados pessoais
- **Correção**: Validar se o usuário só pode acessar seus próprios dados

## Estrutura dos Testes

Cada módulo contém:
- `server.py` - Implementação vulnerável
- `solution.py` - Implementação corrigida
- `test_a01.py` - Testes automatizados
- `README.md` - Documentação específica

## Tecnologias Utilizadas

- **FastAPI** - Framework web moderno para Python
- **PostgreSQL** - Banco de dados
- **JWT** - Autenticação baseada em tokens
- **pytest** - Framework de testes
- **SQLAlchemy** - ORM para Python