# guardrail code

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0%2B-000000.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.1.0--beta-success.svg)](https://github.com/suelio/guardrail-code/releases/tag/v0.1.0-beta)
[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-0a66c2.svg)](https://suelio.github.io/guardrail-code/)

**Language / Idioma:** [Português (BR)](README.md) | English

**guardrail code** is a local web platform and Python static analysis engine built to audit projects before any `git push` or production deployment, focusing on AI-assisted coding ("vibe coding") and data science workflows.

It prevents silent exposure risks by inspecting hardcoded credentials, databases inside public web directories, structural flaws via Python AST, `.gitignore` coverage, AI-hallucinated PyPI packages, and known CVEs (OSV.dev), while generating ready-to-use guardrails to keep coding agents under strict rules.

---

## Core features

### 1. Fast security and secret scanning (`SECRETS` and `EXPOSED_DATA`)
- **Keys and tokens detection**: identifies OpenAI, Google/Gemini, AWS, GitHub, and Stripe keys, literal JWTs, PEM/SSH private keys, and sensitive assignments with automatic value masking (`****`) in the UI and exported reports.
- **Exposed databases and files**: flags database URIs containing credentials, `.env` files missing from `.gitignore`, local databases (`.sqlite`, `.db`, `.duckdb`) inside public folders (`public/`, `static/`, `htdocs/`), `debug=True`, and unrestricted `CORS(*)`.
- **On-demand execution**: never runs scans or preloads sample projects on startup; every scan reads live files from the selected folder with a step-by-step loading overlay and a **`Clear data`** button.

### 2. Static analysis for Python and data science (`SAST_DS` and `DEPLOY_TRAPS`)
- **Python `ast` inspection**: analyzes `.py` files and Jupyter `.ipynb` cells to detect SQL injection (f-strings/concatenation), unsafe deserialization (`pickle.load`, `joblib.load`, `torch.load` without `weights_only=True`, `yaml.load` without `SafeLoader`), `eval()`, `exec()`, `subprocess(..., shell=True)`, and `verify=False`.
- **Notebook hygiene and portability**: detects saved outputs inside `.ipynb` files, hardcoded `localhost`/`127.0.0.1` URLs (ignoring safe `os.getenv` fallbacks), and workstation-specific absolute paths.
- **Explicit inline suppression**: supports `# guardrail-ignore` on intentional lines.

### 3. Git and `.gitignore` protection with confirmation (`GIT_HYGIENE`)
- Audits essential `.gitignore` coverage and runs `git ls-files` to catch sensitive files already tracked in the Git index.
- Hardens `.gitignore` automatically only after explicit confirmation via a modal previewing every pattern to be appended.

### 4. Environment, runtime, and modules audit (`ENVIRONMENT`)
- Compares the local Python version against the latest official release series and detects Anaconda or standard runtimes.
- Checks packages in `requirements.txt` (or installed in the environment) against **PyPI** (flagging AI-hallucinated packages returning HTTP 404) and **OSV.dev** (known CVEs).
- Requires explicit confirmation before any upgrade, warning that rolling back to a previous version (downgrade) afterward must be done manually via terminal.

### 5. Bilingual skills and guardrails builder (`/vibe-coding-guardrail`)
- Generates files matching the active interface language (**PT-BR** or **EN**): `skills/vibe-coding-guardrail/SKILL.md`, `GEMINI.md`, `CLAUDE.md`, and `.cursorrules`.
- Includes an interactive checkbox builder (strict deploy trigger lock, zero hardcoded secrets, `.gitignore` rules, preventive SAST, portability, and PyPI verification) with one-click installation into the target folder.

### 6. Thematic test catalog and GitHub updates (`/testes`)
- Organizes all checks into thematic blocks (`Security and credentials`, `Databases and files`, `Deploy and configuration`, `Data science and SAST`, `Git and versioning`, `Environment, runtime, and modules`).
- Lets you enable or disable any rule individually (both on `/testes` and directly on finding cards), install optional modules (`Privacy and data protection`, `Docker and containers`, `Cloud and infrastructure`), create custom regex rules, and check/download new modules directly from the project's GitHub repository.

### 7. Executive reports and RAM management
- Exports standalone **HTML** (print/PDF-ready), **Markdown**, and **JSON** reports with scan duration displayed in seconds (`0.00s`).
- Runs explicit RAM cleanup (`gc.collect(2)` and OS working-set trimming via `core/memory_manager.py`) after each scan.

---

## Scoring system (grade A–F)

Each finding deducts a severity weight (`CRITICAL: 22`, `HIGH: 12`, `MEDIUM: 5`, `LOW: 2`) starting from 100 points:

| Grade | Score range | Publish verdict |
| --- | --- | --- |
| **A** | 90 – 100 (0 critical) | Ready to publish |
| **B** | 75 – 89 (0 critical) | Good, minor adjustments recommended |
| **C** | 55 – 74 | Attention needed before deploy |
| **D** | 35 – 54 | Elevated risk — fix before push |
| **F** | 0 – 34 | Blocked: critical exposure risk |

---

## Repository structure

```text
guardrail-code/
|-- .github/
|   `-- workflows/
|       `-- ci.yml                    # Automated CI (Python 3.11, 3.12, and 3.13)
|-- core/                             # Scanning engine and audit modules
|   |-- __init__.py                   # Core package exports
|   |-- rules_catalog.py              # Regex rules, SAST docs, and optional modules
|   |-- scanner_engine.py             # os.scandir walker, Python AST, and deduplication
|   |-- git_auditor.py                # .gitignore and git ls-files audit/hardening
|   |-- env_updater.py                # Python, PyPI (404/version), and OSV.dev checks
|   |-- guardrail_generator.py        # Bilingual guardrail templates and builder
|   |-- preferences_manager.py        # Rule toggles, custom rules, and GitHub updates
|   |-- memory_manager.py             # Explicit RAM cleanup (gc.collect + working set)
|   `-- report_exporter.py            # HTML, Markdown, and JSON exporters
|-- docs/
|   `-- index.html                    # Static landing page published on GitHub Pages
|-- skills/
|   `-- vibe-coding-guardrail/
|       `-- SKILL.md                  # Portable preventive skill for AI coding agents
|-- static/
|   |-- css/style.css                 # Material 3 styling and loading overlay
|   `-- js/app.js                     # Bilingual UI, persistence, and modals
|-- templates/
|   |-- index.html                    # Main security auditor dashboard
|   `-- tests_catalog.html            # Thematic /testes catalog subpage
|-- tests/
|   `-- test_guardrail_code.py        # unittest suite (100/100 self-scan and security)
|-- app.py                            # Flask server, REST API, and security headers
|-- requirements.txt                  # Minimal dependencies (Flask)
|-- VERSION                           # Current version (0.1.0-beta)
|-- CHANGELOG.md                      # Release changelog
|-- ATTRIBUTIONS.md                   # Third-party libraries and public API credits
|-- LICENSE                           # MIT License
|-- README.md                         # Portuguese (BR) documentation
`-- README.en.md                      # English documentation
```

---

## Installation and execution

### Using Anaconda / Conda (recommended)

```bash
git clone https://github.com/suelio/guardrail-code.git
cd guardrail-code
pip install -r requirements.txt
python app.py
```

### Using a standard virtual environment (`venv`)

```bash
git clone https://github.com/suelio/guardrail-code.git
cd guardrail-code
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux / macOS
pip install -r requirements.txt
python app.py
```

Once the server is running, open:
- **Main auditor:** `http://127.0.0.1:5006`
- **Tests catalog:** `http://127.0.0.1:5006/testes`

### Running automated tests

```bash
python -m unittest discover tests -v
```

---

## Programmatic usage (Python API)

```python
from core import ProjectSecurityScanner, export_markdown_report

scanner = ProjectSecurityScanner()
result = scanner.scan_directory("./my-project", lang="en")

print(f"Grade: {result['grade']} ({result['score']}/100) in {result['scan_time_s']}s")
markdown_report = export_markdown_report(result, lang="en")
```

---

## Author

- **Suelio Lima**
  - GitHub: [@suelio](https://github.com/suelio)
  - Repository: [github.com/suelio/guardrail-code](https://github.com/suelio/guardrail-code)
  - Project page: [suelio.github.io/guardrail-code](https://suelio.github.io/guardrail-code/)

---

## License and attributions

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details and [ATTRIBUTIONS.md](ATTRIBUTIONS.md) for third-party library and public API credits.
