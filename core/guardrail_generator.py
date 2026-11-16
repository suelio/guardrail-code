"""Generate and install AI coding guardrails and workspace rules in PT-BR or EN."""

import os
import re
from typing import Dict, Any, List
from .rules_catalog import normalize_lang

GUARDRAIL_PILLARS_PT: List[Dict[str, str]] = [
    {
        "key": "deploy_lock",
        "title": "Publicação somente com autorização explícita",
        "detail": "Bloqueia deploy, upload ou git push automático. A IA só publica quando você digitar exatamente o comando de confirmação.",
    },
    {
        "key": "no_secrets",
        "title": "Zero senhas e chaves no código",
        "detail": "Proíbe API keys, URIs com senha e tokens fixos em .py, .js ou notebooks; exige leitura via os.getenv() e .env.",
    },
    {
        "key": "gitignore_notebooks",
        "title": "Blindagem automática de .gitignore e notebooks",
        "detail": "Exige .gitignore cobrindo .env, bancos (.sqlite/.db/.duckdb) e modelos .pkl, além de limpar outputs de arquivos .ipynb.",
    },
    {
        "key": "sast_queries",
        "title": "SAST preventivo (SQL injection, pickle e debug)",
        "detail": "Obriga queries parametrizadas, proíbe pickle/yaml.load sem SafeLoader, eval/shell=True, verify=False e debug=True.",
    },
    {
        "key": "portability",
        "title": "Portabilidade (sem localhost ou caminhos C:\\Users)",
        "detail": "Garante uso de URLs relativas/variáveis de ambiente e caminhos baseados em Path(__file__).resolve().parent.",
    },
    {
        "key": "pypi_verify",
        "title": "Verificação de pacotes reais no PyPI",
        "detail": "Impede instalação cega de dependências alucinadas pela IA antes de checar no repositório oficial.",
    },
]

GUARDRAIL_PILLARS_EN: List[Dict[str, str]] = [
    {
        "key": "deploy_lock",
        "title": "Publish only with explicit command authorization",
        "detail": "Blocks automatic deploy, upload, or git push. The AI publishes only after you type the exact confirmation trigger.",
    },
    {
        "key": "no_secrets",
        "title": "Zero hardcoded passwords or API keys",
        "detail": "Bans literal keys, database URIs, and tokens inside code; enforces os.getenv() backed by .env.",
    },
    {
        "key": "gitignore_notebooks",
        "title": "Protected .gitignore and clean Jupyter notebooks",
        "detail": "Requires .gitignore coverage for .env, local databases, and .pkl models plus clearing .ipynb cell outputs.",
    },
    {
        "key": "sast_queries",
        "title": "Preventive SAST (SQL injection, pickle, debug)",
        "detail": "Enforces parameterized SQL, safe_load YAML, and forbids unsafe pickle, eval/shell=True, verify=False, and debug=True.",
    },
    {
        "key": "portability",
        "title": "Deploy portability (no localhost or workstation paths)",
        "detail": "Uses environment URLs and Path(__file__).resolve().parent instead of workstation-specific paths.",
    },
    {
        "key": "pypi_verify",
        "title": "PyPI package verification",
        "detail": "Prevents hallucinated dependency installs by checking package existence on PyPI first.",
    },
]

HOW_TO_CREATE_SKILL_PT: List[Dict[str, str]] = [
    {
        "step": "1. Escolha o formato e a pasta",
        "text": "Para usar em qualquer conversa com /nome-da-skill, salve em skills/<nome-da-skill>/SKILL.md (ou em ~/.gemini/config/skills/<nome>/SKILL.md). Para regras na raiz, use GEMINI.md, CLAUDE.md ou .cursorrules.",
    },
    {
        "step": "2. Defina o cabeçalho YAML (frontmatter)",
        "text": "Comece o arquivo SKILL.md com --- contendo name: vibe-coding-guardrail (o nome exato do comando /) e description: explicando quando o agente deve ativá-la.",
    },
    {
        "step": "3. Escreva regras claras e verificáveis",
        "text": "Defina a frase exata para liberar deploy (ex.: 'publicar'), proibição de senhas fixas, uso de .gitignore e limpeza de outputs.",
    },
    {
        "step": "4. Instale direto no seu projeto",
        "text": "Escolha ou gere sua skill no editor ao lado e salve na pasta selecionada com um clique.",
    },
]

HOW_TO_CREATE_SKILL_EN: List[Dict[str, str]] = [
    {
        "step": "1. Pick the folder and file structure",
        "text": "For slash-command invocation (/skill-name), place skills/<skill-name>/SKILL.md in your project or ~/.gemini/config/skills/<name>/SKILL.md. For root rules, save GEMINI.md, CLAUDE.md, or .cursorrules.",
    },
    {
        "step": "2. Add YAML frontmatter metadata",
        "text": "Start SKILL.md with --- specifying name: vibe-coding-guardrail (matching the slash command) and a clear description of when the agent should load it.",
    },
    {
        "step": "3. Define strict, testable guardrails",
        "text": "Specify exact deploy trigger phrases (e.g. 'publish'), environment variable lookups, .gitignore rules, parameterized SQL, and comment clarity.",
    },
    {
        "step": "4. Install directly into your workspace",
        "text": "Toggle your preferred rules below, customize the skill command name, and click Save to selected project.",
    },
]

_VIBE_GUARDRAIL_SKILL_PT = """---
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
- Substitua `http://localhost`, `127.0.0.1` e caminhos físicos (`C:\\Users\\...`, `/home/...`) por variáveis de ambiente ou `Path(__file__).resolve().parent`.
- Confira se o pacote existe oficialmente no PyPI antes de instalar qualquer biblioteca sugerida pela IA.
"""

_VIBE_GUARDRAIL_SKILL_EN = """---
name: vibe-coding-guardrail
description: >-
  Preventive security guardrail for AI-assisted coding and data science sessions.
  Blocks unapproved deploys, hardcoded secrets, SQL injection, pickle RCE, and hallucinated packages.
---

# Vibe coding security guardrail

Follow these mandatory rules before creating, modifying, or publishing any project file.

## 1. Explicit publish and Git confirmation
- Never publish, deploy, push, or upload to remote servers automatically.
- Execute deployment steps only when the user types an explicit authorization phrase such as **"publish"** or **"deploy approved"**.
- Show a complete summary of created, modified, and removed files before running any `git commit` or `git push`.

## 2. Secrets and environment hygiene
- Never hardcode API keys, tokens, database passwords, or JWT secrets in source code.
- Load all credentials from environment variables (`os.getenv(...)`) backed by `.env`.
- Maintain an empty `.env.example` template with placeholder keys only.

## 3. Protected `.gitignore` and clean notebooks
- Verify `.gitignore` blocks `.env`, `.env.*`, `*.pem`, `*.key`, `*.sqlite`, `*.db`, `*.duckdb`, `*.pkl`, `__pycache__/`, and `.ipynb_checkpoints/`.
- Clear all cell outputs in `.ipynb` files before committing so data samples and local tracebacks do not leak.

## 4. Secure code patterns (SAST and data)
- Always use parameterized SQL queries (`cursor.execute("SELECT ... WHERE id = %s", (uid,))`). Never build queries with f-strings or concatenation.
- Avoid `pickle.load()`, `joblib.load()`, or untrusted `torch.load()` without `weights_only=True`; prefer Parquet, JSON, or Safetensors.
- Replace `yaml.load()` with `yaml.safe_load()` and never call `eval()`, `exec()`, or `subprocess(..., shell=True)` with external data.
- Disable `debug=True`, restrict CORS origins explicitly, and keep TLS verification enabled (`verify=True`).

## 5. Deploy portability and real dependencies
- Replace `http://localhost`, `127.0.0.1`, and local machine paths (`C:\\Users\\...`, `/home/...`) with relative paths or environment settings.
- Confirm package existence on PyPI before installing dependencies suggested by AI assistants.
"""

_WORKSPACE_RULES_PT = """# Guardrail de segurança e higiene para IA (GEMINI.md / CLAUDE.md)

## Regra absoluta de publicação
- Nunca faça deploy remoto, `git push` ou upload sem o usuário escrever expressamente **"publicar"** ou confirmar explicitamente o envio.
- Antes de qualquer commit, liste exatamente os arquivos alterados e confira `git status` para garantir que nenhum `.env` ou banco local será enviado.

## Credenciais e dados
- Nunca grave senhas, chaves de API (`OPENAI_API_KEY`, `GEMINI_API_KEY`, etc.) ou strings `postgresql://<user>:<password>@<host>/<db>` direto no código.
- Leia todas as credenciais com `os.getenv(...)` e garanta que `.env`, `*.sqlite`, `*.db`, `*.duckdb` e `*.pkl` estejam no `.gitignore`.

## Código seguro e portabilidade
- Parametrize todas as consultas SQL (proibido montar SQL com f-string ou `+`).
- Não use `debug=True`, `verify=False`, `eval()`, `shell=True`, `yaml.load()` sem `SafeLoader` nem `pickle.load()` em arquivos externos.
- Substitua URLs `localhost` e caminhos fixos (`C:\\Users\\...`) por variáveis de ambiente e `Path(__file__).resolve().parent`.
- Limpe outputs de notebooks `.ipynb` antes de commitar e confira se bibliotecas sugeridas pela IA existem no PyPI.
"""

_WORKSPACE_RULES_EN = """# AI security and hygiene guardrail (GEMINI.md / CLAUDE.md)

## Strict deployment rule
- Never run remote deployments, `git push`, or server uploads unless the user explicitly commands **"publish"**.
- Always show changed files and verify `git status` before committing so no `.env` or local database leaks.

## Credentials and data protection
- Never write passwords, API keys (`OPENAI_API_KEY`, `GEMINI_API_KEY`), or `postgresql://<user>:<password>@<host>/<db>` strings directly into code.
- Load secrets with `os.getenv(...)` and ensure `.env`, `*.sqlite`, `*.db`, `*.duckdb`, and `*.pkl` remain in `.gitignore`.

## Safe code and portability
- Parameterize all SQL queries; never assemble SQL strings with f-strings or concatenation.
- Avoid `debug=True`, `verify=False`, `eval()`, `shell=True`, `yaml.load()` without `SafeLoader`, and untrusted `pickle.load()`.
- Replace `localhost` URLs and local paths (`C:\\Users\\...`) with environment variables and `Path(__file__).resolve().parent`.
- Clear Jupyter `.ipynb` outputs before commits and verify AI-suggested packages on PyPI.
"""

_CURSOR_RULES_PT = """# Guardrail de segurança para vibe coding (.cursorrules)

Você está auxiliando um desenvolvedor. Cumpra estas regras em todas as respostas e edições:
1. BLOQUEIO DE DEPLOY: Nunca execute scripts de deploy nem `git push` sem o usuário comandar expressamente "publicar".
2. ZERO SENHAS NO CÓDIGO: Nunca escreva senhas, chaves de API, tokens ou URLs de banco com credenciais. Use `os.getenv()`.
3. CHECAGEM DE .gitignore: Garanta `.env`, `.env.*`, `*.pem`, `*.sqlite`, `*.db`, `*.duckdb` e `*.pkl` ignorados antes de commitar.
4. SAST SEGURO: Parametrize consultas SQL (`%s` / `?`). Proibido `eval()`, `exec()`, `subprocess(..., shell=True)`, `verify=False`, `debug=True` ou `yaml.load()` sem `SafeLoader`.
5. SEGURANÇA EM DADOS: Prefira Parquet/JSON/Safetensors no lugar de `pickle.load()` e lembre de limpar outputs de `.ipynb`.
6. SEM LOCALHOST FIXO: Use variáveis de ambiente e `Path(__file__).resolve().parent` em vez de `http://127.0.0.1` ou `C:\\Users\\...`.
"""

_CURSOR_RULES_EN = """# Vibe coding security guardrail (.cursorrules / copilot-instructions.md)

You are assisting a developer. Enforce these rules on every response and edit:
1. DEPLOY LOCK: Never run deploy scripts or `git push` unless the user explicitly commands "publish".
2. NO SECRETS IN CODE: Never output hardcoded passwords, API keys, tokens, or database credentials. Use `os.getenv()`.
3. GITIGNORE CHECK: Ensure `.env`, `.env.*`, `*.pem`, `*.sqlite`, `*.db`, `*.duckdb`, and `*.pkl` are ignored before committing.
4. SAFE SAST: Always parameterize SQL queries (`%s` / `?`). Never use `eval()`, `exec()`, `subprocess(..., shell=True)`, `verify=False`, `debug=True`, or `yaml.load()` without `SafeLoader`.
5. DATA SAFETY: Prefer Parquet/JSON/Safetensors over `pickle.load()`. Clear `.ipynb` outputs before Git commits.
6. NO HARDCODED LOCALHOST: Use environment variables and `Path(__file__).resolve().parent` instead of `http://127.0.0.1` or `C:\\Users\\...`.
"""

GUARDRAIL_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "vibe_guardrail_skill": {
        "key": "vibe_guardrail_skill",
        "title": "Skill preventiva de vibe coding (/vibe-coding-guardrail)",
        "title_en": "Preventive vibe coding skill (/vibe-coding-guardrail)",
        "relative_install_path": os.path.join("skills", "vibe-coding-guardrail", "SKILL.md"),
        "download_name": "SKILL.md",
        "description": "Skill portátil compatível com Antigravity e Claude Code. Impede publicação acidental, vazamento de senhas e erros SAST.",
        "description_en": "Portable SKILL.md compatible with Antigravity and Claude Code. Prevents accidental deploys, hardcoded secrets, and SAST bugs.",
        "content_pt": _VIBE_GUARDRAIL_SKILL_PT,
        "content_en": _VIBE_GUARDRAIL_SKILL_EN,
    },
    "workspace_gemini_md": {
        "key": "workspace_gemini_md",
        "title": "Regras permanentes do projeto (GEMINI.md)",
        "title_en": "Permanent workspace rules (GEMINI.md)",
        "relative_install_path": "GEMINI.md",
        "download_name": "GEMINI.md",
        "description": "Arquivo carregado automaticamente na raiz do repositório para guiar o agente em toda nova conversa.",
        "description_en": "Loaded automatically from the repository root in every new AI session.",
        "content_pt": _WORKSPACE_RULES_PT,
        "content_en": _WORKSPACE_RULES_EN,
    },
    "workspace_claude_md": {
        "key": "workspace_claude_md",
        "title": "Regras permanentes do projeto (CLAUDE.md)",
        "title_en": "Permanent workspace rules (CLAUDE.md)",
        "relative_install_path": "CLAUDE.md",
        "download_name": "CLAUDE.md",
        "description": "Versão padrão CLAUDE.md para manter os mesmos guardrails no Claude Code.",
        "description_en": "Standard CLAUDE.md format enforcing identical guardrails in Claude Code.",
        "content_pt": _WORKSPACE_RULES_PT,
        "content_en": _WORKSPACE_RULES_EN,
    },
    "cursor_rules": {
        "key": "cursor_rules",
        "title": "Regras para Cursor / Copilot (.cursorrules)",
        "title_en": "Cursor / Copilot rules (.cursorrules)",
        "relative_install_path": ".cursorrules",
        "download_name": ".cursorrules",
        "description": "Arquivo de instruções curtas e diretas para Cursor IDE e assistentes inline.",
        "description_en": "Concise instruction file tailored for Cursor IDE and inline coding assistants.",
        "content_pt": _CURSOR_RULES_PT,
        "content_en": _CURSOR_RULES_EN,
    },
}


def build_custom_skill(
    skill_slug: str,
    publish_keyword: str = "publicar",
    enabled_pillars: List[str] = None,
    lang: str = "pt",
) -> Dict[str, Any]:
    """Assemble a custom SKILL.md localized in PT-BR or EN according to the active language."""
    is_en = normalize_lang(lang) == "en"
    clean_slug = re.sub(r"[^a-z0-9-]", "-", (skill_slug or "meu-guardrail").strip().lower()).strip("-") or "meu-guardrail"
    trigger = (publish_keyword or ("publish" if is_en else "publicar")).strip()
    selected = set(enabled_pillars or [p["key"] for p in GUARDRAIL_PILLARS_PT])

    if is_en:
        sections = [
            f"---\nname: {clean_slug}\ndescription: >-\n  Custom vibe-coding safety guardrail triggered via /{clean_slug}. Enforce strict deployment approval, secret hygiene, and safe code checks.\n---",
            "",
            f"# Custom AI guardrail (`/{clean_slug}`)",
            "",
            "Follow these mandatory safety rules in every coding session:",
            "",
        ]
        if "deploy_lock" in selected:
            sections.extend([
                "## 1. Strict deploy confirmation",
                f'- Never deploy, upload, or push to production unless the user explicitly writes **"{trigger}"**.',
                "- Summarize modified files and git status before any commit.",
                "",
            ])
        if "no_secrets" in selected:
            sections.extend([
                "## 2. Zero hardcoded secrets",
                "- Never write passwords, API keys, tokens, or database credentials directly in code.",
                "- Always load secrets via `os.getenv(...)` stored in `.env`.",
                "",
            ])
        if "gitignore_notebooks" in selected:
            sections.extend([
                "## 3. Protected .gitignore and Jupyter notebooks",
                "- Verify `.gitignore` covers `.env`, `.env.*`, `*.pem`, `*.sqlite`, `*.db`, `*.duckdb`, and `*.pkl`.",
                "- Clear all `.ipynb` outputs before committing.",
                "",
            ])
        if "sast_queries" in selected:
            sections.extend([
                "## 4. Safe SAST and data practices",
                "- Parameterize all SQL queries; never format SQL strings with f-strings.",
                "- Avoid `pickle.load()`, `yaml.load()`, `eval()`, `shell=True`, `verify=False`, and `debug=True`.",
                "",
            ])
        if "portability" in selected:
            sections.extend([
                "## 5. Deploy portability",
                "- Avoid hardcoded `localhost`, `127.0.0.1`, or `C:\\Users\\...` paths.",
                "- Build paths with `Path(__file__).resolve().parent`.",
                "",
            ])
        if "pypi_verify" in selected:
            sections.extend([
                "## 6. Real dependencies on PyPI",
                "- Verify package existence on PyPI before installing new dependencies.",
                "",
            ])
    else:
        sections = [
            f"---\nname: {clean_slug}\ndescription: >-\n  Guardrail personalizado de segurança para vibe coding ativado por /{clean_slug}. Exige confirmação de deploy, proteção de senhas e validação de código.\n---",
            "",
            f"# Guardrail personalizado (`/{clean_slug}`)",
            "",
            "Cumpra obrigatoriamente estas regras de segurança em todas as sessões:",
            "",
        ]
        if "deploy_lock" in selected:
            sections.extend([
                "## 1. Bloqueio estrito de publicação",
                f'- Nunca faça deploy, upload remoto ou `git push` a menos que o usuário escreva expressamente **"{trigger}"**.',
                "- Apresente o resumo explícito dos arquivos alterados e do `git status` antes de qualquer commit.",
                "",
            ])
        if "no_secrets" in selected:
            sections.extend([
                "## 2. Zero senhas ou chaves no código",
                "- Nunca escreva senhas, API keys, tokens ou credenciais de banco direto no código.",
                "- Carregue segredos exclusivamente via `os.getenv(...)` usando um arquivo `.env` local.",
                "",
            ])
        if "gitignore_notebooks" in selected:
            sections.extend([
                "## 3. Blindagem de .gitignore e notebooks",
                "- Confirme que `.gitignore` bloqueia `.env`, `.env.*`, `*.pem`, `*.sqlite`, `*.db`, `*.duckdb` e `*.pkl`.",
                "- Limpe todas as saídas (outputs) de notebooks `.ipynb` antes do commit.",
                "",
            ])
        if "sast_queries" in selected:
            sections.extend([
                "## 4. Código seguro (SAST e dados)",
                "- Parametrize todas as consultas SQL; nunca monte SQL com f-string ou soma de texto.",
                "- Evite `pickle.load()`, `yaml.load()`, `eval()`, `shell=True`, `verify=False` e `debug=True`.",
                "",
            ])
        if "portability" in selected:
            sections.extend([
                "## 5. Portabilidade de deploy",
                "- Não deixe `localhost`, `127.0.0.1` ou caminhos fixos como `C:\\Users\\...` no código.",
                "- Construa caminhos com `Path(__file__).resolve().parent`.",
                "",
            ])
        if "pypi_verify" in selected:
            sections.extend([
                "## 6. Dependências reais no PyPI",
                "- Verifique se o pacote existe oficialmente no PyPI antes de instalar.",
                "",
            ])

    return {
        "status": "success",
        "lang": "en" if is_en else "pt",
        "skill_name": clean_slug,
        "relative_install_path": os.path.join("skills", clean_slug, "SKILL.md").replace("\\", "/"),
        "download_name": f"SKILL-{clean_slug}.md",
        "content": "\n".join(sections),
    }


def list_guardrail_templates(lang: str = "pt") -> Dict[str, Any]:
    """Return guardrail templates, safety pillars, and skill creation guide in active language."""
    code = normalize_lang(lang)
    is_en = code == "en"
    pillars = GUARDRAIL_PILLARS_EN if is_en else GUARDRAIL_PILLARS_PT
    steps = HOW_TO_CREATE_SKILL_EN if is_en else HOW_TO_CREATE_SKILL_PT

    templates = []
    for tpl in GUARDRAIL_TEMPLATES.values():
        templates.append({
            "key": tpl["key"],
            "title": tpl["title_en"] if is_en else tpl["title"],
            "relative_install_path": tpl["relative_install_path"].replace("\\", "/"),
            "download_name": tpl["download_name"],
            "description": tpl["description_en"] if is_en else tpl["description"],
            "content": tpl["content_en"] if is_en else tpl["content_pt"],
        })

    return {
        "status": "success",
        "lang": code,
        "pillars": pillars,
        "how_to_create_steps": steps,
        "templates": templates,
    }


def install_guardrail_to_project(
    target_dir: str,
    template_key: str,
    custom_content: str = "",
    custom_skill_slug: str = "",
    lang: str = "pt",
) -> Dict[str, Any]:
    """Write the selected or custom guardrail skill inside the target project directory."""
    code = normalize_lang(lang)
    is_en = code == "en"
    if not target_dir or not os.path.isdir(target_dir):
        raise FileNotFoundError(
            f"Target directory not found: '{target_dir}'" if is_en else f"Diretório alvo não encontrado: '{target_dir}'"
        )

    if template_key == "custom_skill":
        clean_slug = re.sub(r"[^a-z0-9-]", "-", (custom_skill_slug or "meu-guardrail").strip().lower()).strip("-") or "meu-guardrail"
        rel_path = os.path.join("skills", clean_slug, "SKILL.md")
        content = (custom_content or "").strip() or build_custom_skill(clean_slug, lang=code)["content"]
    else:
        if template_key not in GUARDRAIL_TEMPLATES:
            raise ValueError(
                f"Unknown guardrail template: '{template_key}'" if is_en else f"Template de guardrail desconhecido: '{template_key}'"
            )
        tpl = GUARDRAIL_TEMPLATES[template_key]
        rel_path = tpl["relative_install_path"]
        default_content = tpl["content_en"] if is_en else tpl["content_pt"]
        content = (custom_content or "").strip() or default_content

    dest_path = os.path.realpath(os.path.join(target_dir, rel_path))
    abs_root = os.path.realpath(target_dir)
    if os.path.commonpath([abs_root, dest_path]) != abs_root:
        raise PermissionError("Target path escapes selected project folder.")

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        f.write(content.rstrip() + "\n")

    normalized_rel = rel_path.replace("\\", "/")
    return {
        "status": "success",
        "installed_path": dest_path,
        "relative_path": normalized_rel,
        "message": (
            f"Guardrail saved to {normalized_rel}."
            if is_en else
            f"Guardrail salvo em {normalized_rel}."
        ),
    }
