---
name: vibe-coding-guardrail
description: >-
  Guardrail preventivo de segurança para programação assistida por IA e ciência de dados.
  Bloqueia deploy sem autorização, senhas fixas no código, SQL injection, pickle RCE e pacotes alucinados.
---

# Guardrail de segurança para vibe coding

Siga estas regras obrigatórias antes de criar, editar ou publicar qualquer arquivo do projeto.

## 1. Bloqueio estrito de publicação e Git
- Nunca publique, faça deploy remoto, upload ou `git push` automaticamente.
- Execute scripts de publicação apenas quando o usuário escrever expressamente **"publicar"** ou **"deploy aprovado"**.
- Sempre mostre um resumo explícito dos arquivos criados, editados ou removidos antes de registrar qualquer commit.

## 2. Zero senhas e segredos no código
- Nunca escreva chaves de API, senhas de banco, tokens JWT ou chaves privadas dentro de arquivos `.py`, `.js`, `.ipynb` ou `.sql`.
- Carregue credenciais exclusivamente via variáveis de ambiente (`os.getenv(...)`) apoiadas em arquivo `.env`.
- Mantenha um arquivo `.env.example` apenas com chaves vazias de modelo.

## 3. Higiene de `.gitignore` e notebooks
- Confirme que `.gitignore` bloqueia `.env`, `.env.*`, `*.pem`, `*.key`, `*.sqlite`, `*.db`, `*.duckdb`, `*.pkl`, `__pycache__/` e `.ipynb_checkpoints/`.
- Limpe as saídas (outputs) de arquivos `.ipynb` antes de commitar para não vazar linhas de dados ou caminhos locais.

## 4. Padrões seguros de código (SAST e dados)
- Use sempre queries SQL parametrizadas (`cursor.execute("SELECT ... WHERE id = %s", (uid,))`). Nunca monte SQL com f-string ou concatenação `+`.
- Evite `pickle.load()`, `joblib.load()` ou `torch.load()` sem `weights_only=True` em arquivos externos; prefira Parquet, JSON ou Safetensors.
- Troque `yaml.load()` por `yaml.safe_load()` e nunca use `eval()`, `exec()` ou `subprocess(..., shell=True)` com entradas externas.
- Desative `debug=True`, restrinja origens de CORS explicitamente e mantenha verificação TLS ativa (`verify=True`).

## 5. Portabilidade e dependências reais
- Substitua `http://localhost`, `127.0.0.1` e caminhos físicos (`C:\Users\...`, `/home/...`) por variáveis de ambiente ou `Path(__file__).resolve().parent`.
- Confira se o pacote existe oficialmente no PyPI antes de instalar qualquer biblioteca sugerida pela IA.
