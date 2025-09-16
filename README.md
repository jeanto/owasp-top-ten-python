# OWASP Top 10 - Python Edition

Repositório prático e didático para demonstrar as principais vulnerabilidades de segurança em aplicações web segundo o OWASP Top 10, implementado em Python com FastAPI.

> **Este projeto é uma adaptação em Python, baseada no repositório original [owasp-top-ten-workshop](https://github.com/nearform/owasp-top-ten-workshop.git) criado por NearForm, licenciado sob [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/). Todas as modificações e novas implementações feitas aqui também estão licenciadas sob CC-BY-SA-4.0. Se reutilizar este projeto, mantenha esta licença e referência ao criador original.**


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