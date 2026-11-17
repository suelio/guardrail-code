# guardrail code

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0%2B-000000.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.1.0--beta-success.svg)](https://github.com/suelio/guardrail-code/releases/tag/v0.1.0-beta)
[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-0a66c2.svg)](https://suelio.github.io/guardrail-code/)

**Idioma / Language:** Português (BR) | [English](README.en.md)

O **guardrail code** é uma plataforma web local e motor de análise estática em Python desenvolvido para auditar projetos antes de qualquer `git push` ou deploy em produção, com foco em código gerado com auxílio de IA ("vibe coding") e fluxos de ciência de dados.

O projeto elimina riscos silenciosos de exposição ao inspecionar credenciais hardcoded, bancos de dados em pastas públicas, falhas estruturais via AST Python, cobertura do `.gitignore`, pacotes alucinados por IA no PyPI, vulnerabilidades conhecidas (OSV.dev) e ainda gera arquivos de guardrail prontos para manter agentes de IA sob controle.

---

## Principais funcionalidades

### 1. Varredura rápida de segurança e segredos (`SECRETS` e `EXPOSED_DATA`)
- **Detecção de chaves e tokens**: identifica credenciais OpenAI, Google/Gemini, AWS, GitHub, Stripe, JWTs literais, chaves privadas PEM/SSH e atribuições sensíveis com mascaramento automático (`****`) na exibição e nos relatórios.
- **Bancos e arquivos expostos**: sinaliza URIs de banco com senha, arquivos `.env` fora do `.gitignore`, bancos locais (`.sqlite`, `.db`, `.duckdb`) dentro de diretórios públicos (`public/`, `static/`, `htdocs/`), `debug=True` e `CORS(*)` irrestrito.
- **Execução sob demanda**: nunca roda código ou pré-carrega exemplos ao abrir; toda leitura é feita ao vivo no diretório escolhido, com tela de loading em etapas e botão **`Limpar dados`**.

### 2. Análise estática para Python e ciência de dados (`SAST_DS` e `DEPLOY_TRAPS`)
- **Inspeção via `ast`**: analisa arquivos `.py` e células de notebooks `.ipynb` para capturar SQL Injection (f-strings/concatenação), desserialização insegura (`pickle.load`, `joblib.load`, `torch.load` sem `weights_only=True`, `yaml.load` sem `SafeLoader`), `eval()`, `exec()`, `subprocess(..., shell=True)` e `verify=False`.
- **Higiene de notebooks e portabilidade**: detecta saídas salvas em `.ipynb`, URLs fixas para `localhost`/`127.0.0.1` (ignorando fallbacks seguros via `os.getenv`) e caminhos absolutos de máquina local.
- **Supressão explícita**: suporta comentário `# guardrail-ignore` em linhas intencionais.

### 3. Proteção Git e `.gitignore` com confirmação (`GIT_HYGIENE`)
- Audita as regras essenciais do `.gitignore` e verifica via `git ls-files` se algum arquivo sensível já foi indexado pelo Git.
- Permite blindar o `.gitignore` automaticamente mediante modal de confirmação prévia listando exatamente as regras que serão gravadas.

### 4. Auditoria de ambiente, runtime e módulos (`ENVIRONMENT`)
- Compara a versão local do Python com a série oficial mais recente e detecta ambientes Anaconda ou padrão.
- Consulta pacotes declarados no `requirements.txt` (ou instalados no ambiente) contra o **PyPI** (identificando nomes alucinados por IA com HTTP 404) e contra a API **OSV.dev** (CVEs conhecidas).
- Exige confirmação explícita antes de executar qualquer atualização, alertando que um eventual rollback/downgrade posterior deve ser feito manualmente via terminal.

### 5. Construtor de skills e guardrails bilíngues (`/vibe-coding-guardrail`)
- Gera arquivos no idioma ativo da interface (**PT-BR** ou **EN**): `skills/vibe-coding-guardrail/SKILL.md`, `GEMINI.md`, `CLAUDE.md` e `.cursorrules`.
- Inclui construtor interativo por checkboxes (bloqueio de deploy sem comando explícito, zero senhas fixas, proteção `.gitignore`, SAST preventivo, portabilidade e checagem PyPI) com instalação em 1 clique na pasta do projeto.

### 6. Catálogo de testes por blocos e extensibilidade (`/testes`)
- Lista todas as verificações separadas por blocos temáticos (`Segurança e credenciais`, `Banco de dados e arquivos`, `Deploy e configuração`, `Ciência de dados e SAST`, `Git e versionamento`, `Ambiente, runtime e módulos`).
- Permite ativar ou desativar qualquer regra individualmente (tanto em `/testes` quanto direto no card do risco), instalar módulos opcionais (`Privacidade e LGPD`, `Docker e containers`, `Cloud e infraestrutura`), criar regras regex próprias e verificar/baixar novos módulos diretamente do repositório oficial no GitHub.

### 7. Relatórios executivos e gestão de memória RAM
- Exporta diagnósticos em **HTML autônomo** (pronto para impressão/PDF), **Markdown** e **JSON**, com tempo de varredura exibido em segundos (`0.00s`).
- Executa limpeza explícita de memória RAM (`gc.collect(2)` e liberação de working set via `core/memory_manager.py`) ao final de cada varredura.

---

## Sistema de pontuação (nota A–F)

Cada achado aplica uma penalidade proporcional à severidade (`CRITICAL: 22`, `HIGH: 12`, `MEDIUM: 5`, `LOW: 2`) a partir de 100 pontos:

| Nota | Faixa de score | Veredito de publicação |
| --- | --- | --- |
| **A** | 90 – 100 (0 críticos) | Pronto para publicar |
| **B** | 75 – 89 (0 críticos) | Bom, com ajustes menores recomendados |
| **C** | 55 – 74 | Atenção necessária antes do deploy |
| **D** | 35 – 54 | Risco elevado — corrija antes de subir |
| **F** | 0 – 34 | Bloqueado: risco crítico de vazamento |

---

## Estrutura do repositório

```text
guardrail-code/
|-- .github/
|   `-- workflows/
|       `-- ci.yml                    # CI automatizado (Python 3.11, 3.12 e 3.13)
|-- core/                             # Motor de análise e módulos de auditoria
|   |-- __init__.py                   # Exports principais do pacote
|   |-- rules_catalog.py              # Regras regex, documentação SAST e módulos opcionais
|   |-- scanner_engine.py             # Varredura com os.scandir, AST Python e deduplicação
|   |-- git_auditor.py                # Auditoria e blindagem de .gitignore e git ls-files
|   |-- env_updater.py                # Checagem Python, PyPI (404/versão) e OSV.dev (CVEs)
|   |-- guardrail_generator.py        # Templates e construtor de skills bilíngues
|   |-- preferences_manager.py        # Persistência de regras, módulos e updates via GitHub
|   |-- memory_manager.py             # Coleta explícita de RAM (gc.collect + working set)
|   `-- report_exporter.py            # Exportação em HTML, Markdown e JSON
|-- docs/
|   `-- index.html                    # Página estática publicada via GitHub Pages
|-- skills/
|   `-- vibe-coding-guardrail/
|       `-- SKILL.md                  # Skill portátil de prevenção para agentes de IA
|-- static/
|   |-- css/style.css                 # Estilização Material 3 + overlay de loading
|   `-- js/app.js                     # Interface bilíngue, persistência e modais
|-- templates/
|   |-- index.html                    # Painel principal de auditoria
|   `-- tests_catalog.html            # Subpágina /testes agrupada por blocos
|-- tests/
|   `-- test_guardrail_code.py        # Suíte unittest (autoauditoria 100/100 e segurança)
|-- app.py                            # Servidor Flask, rotas REST e headers de segurança
|-- requirements.txt                  # Dependências mínimas (Flask)
|-- VERSION                           # Versão atual (0.1.0-beta)
|-- CHANGELOG.md                      # Histórico de alterações da release
|-- ATTRIBUTIONS.md                   # Créditos de bibliotecas e APIs públicas
|-- LICENSE                           # Licença MIT
|-- README.md                         # Documentação principal (PT-BR)
`-- README.en.md                      # Documentação em inglês (EN)
```

---

## Instalação e execução

### Com Anaconda / Conda (recomendado)

```bash
git clone https://github.com/suelio/guardrail-code.git
cd guardrail-code
pip install -r requirements.txt
python app.py
```

### Com ambiente virtual padrão (`venv`)

```bash
git clone https://github.com/suelio/guardrail-code.git
cd guardrail-code
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux / macOS
pip install -r requirements.txt
python app.py
```

Após iniciar o servidor, acesse:
- **Auditor principal:** `http://127.0.0.1:5006`
- **Catálogo de testes:** `http://127.0.0.1:5006/testes`

### Executando os testes automatizados

```bash
python -m unittest discover tests -v
```

---

## Uso programático (API Python)

```python
from core import ProjectSecurityScanner, export_markdown_report

scanner = ProjectSecurityScanner()
resultado = scanner.scan_directory("./meu-projeto", lang="pt")

print(f"Nota: {resultado['grade']} ({resultado['score']}/100) em {resultado['scan_time_s']}s")
relatorio_md = export_markdown_report(resultado, lang="pt")
```

---

## Autor

- **Suelio Lima**
  - GitHub: [@suelio](https://github.com/suelio)
  - Repositório: [github.com/suelio/guardrail-code](https://github.com/suelio/guardrail-code)
  - Página do projeto: [suelio.github.io/guardrail-code](https://suelio.github.io/guardrail-code/)

---

## Licença e atribuições

Distribuído sob os termos da **Licença MIT**. Consulte [LICENSE](LICENSE) para detalhes e [ATTRIBUTIONS.md](ATTRIBUTIONS.md) para os créditos de tecnologias e APIs utilizadas.
