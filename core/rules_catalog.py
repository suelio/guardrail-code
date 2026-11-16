"""Define bilingual security rules, severity weights, and complete test catalog metadata."""

import re
from typing import Dict, List, Any

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 22,
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

CATEGORY_LABELS: Dict[str, str] = {
    "SECRETS": "Segurança e credenciais",
    "EXPOSED_DATA": "Banco de dados e arquivos",
    "DEPLOY_TRAPS": "Deploy e configuração",
    "SAST_DS": "Ciência de dados e SAST",
    "GIT_HYGIENE": "Git e versionamento",
    "ENVIRONMENT": "Ambiente, runtime e módulos",
    "PRIVACY_LGPD": "Privacidade e LGPD",
    "DOCKER_INFRA": "Docker e containers",
    "CLOUD_SSH": "Cloud e infraestrutura",
}

CATEGORY_LABELS_EN: Dict[str, str] = {
    "SECRETS": "Security and credentials",
    "EXPOSED_DATA": "Databases and files",
    "DEPLOY_TRAPS": "Deploy and configuration",
    "SAST_DS": "Data science and SAST",
    "GIT_HYGIENE": "Git and versioning",
    "ENVIRONMENT": "Environment, runtime, and modules",
    "PRIVACY_LGPD": "Privacy and data protection",
    "DOCKER_INFRA": "Docker and containers",
    "CLOUD_SSH": "Cloud and infrastructure",
}


def normalize_lang(lang: str) -> str:
    """Normalize interface language code to either 'en' or default 'pt'."""
    return "en" if str(lang or "").strip().lower().startswith("en") else "pt"


def get_category_label(category: str, lang: str = "pt") -> str:
    """Return the localized category label for the requested UI language."""
    code = normalize_lang(lang)
    mapping = CATEGORY_LABELS_EN if code == "en" else CATEGORY_LABELS
    return mapping.get(category, category)


def pick_lang_text(entry: Dict[str, Any], field: str, lang: str = "pt") -> str:
    """Select the localized rule text with automatic fallback to Portuguese."""
    if normalize_lang(lang) == "en":
        return entry.get(f"{field}_en") or entry.get(field, "")
    return entry.get(field, "")


SENSITIVE_ASSIGN_NAMES = {
    "password", "passwd", "pwd", "senha", "secret", "secret_key", "app_secret",
    "api_key", "apikey", "openai_api_key", "gemini_api_key", "google_api_key",
    "anthropic_api_key", "db_pass", "db_password", "vps_root_password",
    "access_token", "auth_token", "bearer_token", "token", "client_secret",
    "private_key", "jwt_secret", "aws_secret_access_key", "stripe_api_key",
}

PLACEHOLDER_VALUES = {
    "", "none", "null", "true", "false", "changeme", "change_me", "your_key_here",
    "seu_token_aqui", "sua_senha_aqui", "example", "placeholder", "xxx", "****",
}


def mask_secret_value(raw_value: str) -> str:
    """Mask secret literals so reports retain only short prefix and suffix hints."""
    if not raw_value:
        return "****"
    cleaned = raw_value.strip().strip("\"'")
    if len(cleaned) <= 8:
        return cleaned[:2] + "****" if len(cleaned) > 2 else "****"
    return f"{cleaned[:4]}****{cleaned[-4:]}"


def is_placeholder_secret(val: str) -> bool:
    """Skip empty strings and obvious placeholder values to avoid false positives."""
    low = val.strip().strip("\"'").lower()
    if low in PLACEHOLDER_VALUES or len(low) < 4:
        return True
    if low.startswith("<") and low.endswith(">"):
        return True
    if low.startswith("${") or low.startswith("os.environ") or low.startswith("env("):
        return True
    if set(low) <= {"*", "x", "."}:
        return True
    return False


# High-speed line-level regex rules (secrets, DB URIs, localhost, absolute machine paths)
REGEX_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-OPENAI-KEY",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Chave de API OpenAI exposta no codigo",
        "title_en": "Exposed OpenAI API key in source code",
        "pattern": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
        "mask_match": True,
        "plain_why": "Qualquer pessoa que ler este arquivo (ou baixar seu repositorio no GitHub) podera usar sua conta OpenAI e gerar cobrancas na sua fatura em segundos.",
        "plain_why_en": "Anyone who reads this file or clones your repository can consume your OpenAI credits and run up charges on your billing account.",
        "how_to_fix": "Apague a chave do arquivo imediatamente, revogue essa chave no painel da OpenAI e leia o valor via variavel de ambiente.",
        "how_to_fix_en": "Delete the literal key, revoke it in the OpenAI dashboard, and load the new key from an environment variable.",
        "fix_example": "import os\napi_key = os.getenv('OPENAI_API_KEY')",
    },
    {
        "id": "SEC-GOOGLE-KEY",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Chave de API Google / Gemini exposta",
        "title_en": "Exposed Google / Gemini API key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"),
        "mask_match": True,
        "plain_why": "Chaves Google expostas permitem consumo abusivo de cotas de IA, Maps ou nuvem na sua conta Google Cloud.",
        "plain_why_en": "Exposed Google Cloud API keys let unauthorized callers exhaust AI, Maps, or cloud quotas billed to your account.",
        "how_to_fix": "Revogue a chave no Google Cloud Console, restrinja por IP/dominio e guarde a nova apenas no arquivo .env protegido pelo .gitignore.",
        "how_to_fix_en": "Rotate the key in Google Cloud Console, restrict HTTP/IP referrers, and keep it inside a .gitignore-protected .env file.",
        "fix_example": "import os\ngemini_key = os.getenv('GEMINI_API_KEY')",
    },
    {
        "id": "SEC-AWS-KEY",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Chave de acesso AWS exposta",
        "title_en": "Exposed AWS access key ID",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "mask_match": True,
        "plain_why": "Bots varrem o GitHub continuamente em busca de chaves AKIA para sequestrar servidores ou minerar usando sua conta AWS.",
        "plain_why_en": "Automated bots scan public repositories continuously for AKIA credentials to hijack cloud instances or abuse resources.",
        "how_to_fix": "Desative a chave imediatamente no IAM da AWS e utilize AWS Secrets Manager ou variaveis de ambiente fora do Git.",
        "how_to_fix_en": "Deactivate the key in AWS IAM immediately and migrate to IAM roles or AWS Secrets Manager.",
        "fix_example": "aws_key = os.getenv('AWS_ACCESS_KEY_ID')",
    },
    {
        "id": "SEC-GITHUB-TOKEN",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Token pessoal do GitHub exposto",
        "title_en": "Exposed GitHub Personal Access Token",
        "pattern": re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
        "mask_match": True,
        "plain_why": "Com esse token um atacante consegue ler repositorios privados, alterar codigo e injetar malware em seu nome.",
        "plain_why_en": "A leaked GitHub token grants attackers read or write access to your private repositories and automated workflows.",
        "how_to_fix": "Revogue o token em GitHub Settings > Developer settings > Personal access tokens e use credenciais temporarias.",
        "how_to_fix_en": "Revoke the token under GitHub Developer Settings and replace it with short-lived environment credentials.",
        "fix_example": "github_token = os.getenv('GITHUB_TOKEN')",
    },
    {
        "id": "SEC-STRIPE-KEY",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Chave de producao Stripe exposta",
        "title_en": "Exposed live Stripe secret key",
        "pattern": re.compile(r"\b(?:sk_live|rk_live)_[0-9a-zA-Z]{16,}\b"),
        "mask_match": True,
        "plain_why": "Expoe operacoes financeiras, reembolsos e dados de pagamento reais de clientes.",
        "plain_why_en": "Exposes live financial actions, customer payment records, and unauthorized refund risk.",
        "how_to_fix": "Rotacione a chave no dashboard da Stripe e carregue apenas via variavel de ambiente do servidor.",
        "how_to_fix_en": "Roll the live key in your Stripe dashboard and inject it only via server environment variables.",
        "fix_example": "stripe.api_key = os.getenv('STRIPE_SECRET_KEY')",
    },
    {
        "id": "SEC-PRIVATE-KEY",
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "Chave criptografica privada (PEM/SSH) no projeto",
        "title_en": "Private cryptographic key (PEM/SSH) committed in project",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "mask_match": False,
        "plain_why": "Chaves privadas dao acesso direto a servidores VPS, certificados SSL ou assinaturas JWT sem pedir senha.",
        "plain_why_en": "Private keys bypass password authentication and grant direct access to VPS servers, TLS certificates, or token signing.",
        "how_to_fix": "Remova o arquivo/trecho do repositorio, gere um novo par de chaves e armazene a chave privada fora da pasta do codigo.",
        "how_to_fix_en": "Remove the key file from version control, generate a fresh key pair, and store private keys outside the codebase.",
        "fix_example": "# Carregue o caminho via ENV segura: KEY_PATH=/etc/secrets/server.pem",
    },
    {
        "id": "SEC-JWT-LITERAL",
        "category": "SECRETS",
        "severity": "HIGH",
        "method": "Regex",
        "title": "Token JWT fixo encontrado no codigo",
        "title_en": "Hardcoded JWT token literal found",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "mask_match": True,
        "plain_why": "Tokens JWT salvos manualmente no codigo podem conceder sessao autenticada ou revelar payload interno do sistema.",
        "plain_why_en": "Static JWT literals checked into code can expose session authorization or internal claims to anyone inspecting the file.",
        "how_to_fix": "Nunca deixe tokens reais gravados em scripts de teste ou frontend. Gere tokens dinamicamente no momento do login.",
        "how_to_fix_en": "Remove static JWT values from scripts and issue tokens dynamically at authentication time.",
        "fix_example": "headers = {'Authorization': f'Bearer {os.getenv(\"API_TOKEN\")}' }",
    },
    {
        "id": "EXP-DB-URI-CRED",
        "category": "EXPOSED_DATA",
        "severity": "CRITICAL",
        "method": "Regex",
        "title": "String de conexao de banco com usuario e senha expostos",
        "title_en": "Database connection URI contains embedded username and password",
        "pattern": re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|mssql|redis)://[^:\s/\"']+:[^@\s/\"']+@[^\s\"']+",
            re.IGNORECASE,
        ),
        "mask_match": True,
        "plain_why": "Mostra o endereco, usuario e senha reais do seu banco de dados. Se subir para o Git, qualquer pessoa acessa e apaga seus dados.",
        "plain_why_en": "Exposes your database host, user, and password directly. Publishing this URI lets external actors read or wipe your database.",
        "how_to_fix": "Coloque a URL completa apenas dentro de um arquivo .env protegido no .gitignore e leia com os.getenv('DATABASE_URL').",
        "how_to_fix_en": "Store the full connection URI only inside a gitignored .env file and read it with os.getenv('DATABASE_URL').",
        "fix_example": "DATABASE_URL = os.getenv('DATABASE_URL')",
    },
    {
        "id": "DEP-LOCALHOST-REF",
        "category": "DEPLOY_TRAPS",
        "severity": "MEDIUM",
        "method": "Regex",
        "title": "Endereco local (localhost / 127.0.0.1 / 0.0.0.0) fixado no codigo",
        "title_en": "Hardcoded local address (localhost / 127.0.0.1 / 0.0.0.0)",
        "pattern": re.compile(r"(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d{2,5})?"),
        "mask_match": False,
        "plain_why": "O endereco localhost aponta apenas para o seu proprio computador. Quando voce publica na internet, o site dos usuarios falha ao tentar conectar no computador deles.",
        "plain_why_en": "Localhost points back to the visitor's own machine. Once deployed online, client browsers and services fail to reach your backend.",
        "how_to_fix": "Use URLs relativas (/api/...) no frontend ou variaveis de ambiente de producao com fallback local.",
        "how_to_fix_en": "Use relative endpoints (/api/...) on the frontend or read an environment variable with a safe local fallback.",
        "fix_example": "const API_BASE = window.API_URL || '/api'; // Python: os.getenv('API_URL', 'http://127.0.0.1:5000')",
    },
    {
        "id": "DEP-LOCAL-PATH",
        "category": "DEPLOY_TRAPS",
        "severity": "MEDIUM",
        "method": "Regex",
        "title": "Caminho absoluto da sua maquina local chumbado no codigo",
        "title_en": "Absolute local machine filesystem path hardcoded in code",
        "pattern": re.compile(r"(?:[A-Za-z]:\\Users\\[^\s\"'`<>]+|/(?:home|Users)/[a-zA-Z0-9._-]+/[^\s\"'`<>]+)"),
        "mask_match": False,
        "plain_why": "Pastas como C:\\Users\\SeuNome\\... nao existem no servidor VPS ou na maquina de outro membro da equipe, quebrando a execucao ao publicar.",
        "plain_why_en": "User directories like C:\\Users\\YourName\\... do not exist on cloud servers or teammates' machines, causing runtime crashes.",
        "how_to_fix": "Substitua caminhos fixos por caminhos relativos baseados em Path(__file__).resolve().parent ou variaveis de ambiente.",
        "how_to_fix_en": "Build portable paths with Path(__file__).resolve().parent or read data folders from environment settings.",
        "fix_example": "from pathlib import Path\nBASE_DIR = Path(__file__).resolve().parent\nDATA_PATH = BASE_DIR / 'data' / 'arquivo.csv'",
    },
    {
        "id": "EXP-CORS-WILDCARD",
        "category": "EXPOSED_DATA",
        "severity": "MEDIUM",
        "method": "Regex",
        "title": "CORS totalmente aberto (origins = '*')",
        "title_en": "Wildcard CORS configuration (origins = '*')",
        "pattern": re.compile(r"(?:CORS\s*\([^)]*\*|Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"'])", re.IGNORECASE),
        "mask_match": False,
        "plain_why": "Permite que qualquer site desconhecido na internet faca chamadas autenticadas ou consuma diretamente sua API no navegador do usuario.",
        "plain_why_en": "Allows arbitrary third-party websites to invoke your API endpoints directly from a user's browser session.",
        "how_to_fix": "Liste explicitamente apenas os dominios confiaveis do seu frontend na configuracao de CORS.",
        "how_to_fix_en": "Restrict allowed CORS origins exclusively to your trusted production domain names.",
        "fix_example": "CORS(app, origins=['https://seudominio.com.br'])",
    },
]

ENV_KEY_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
GENERIC_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|senha|secret_key|api_key|apikey|db_pass|db_password|"
    r"vps_root_password|access_token|auth_token|client_secret|jwt_secret)\b\s*[:=]\s*['\"]([^'\"]{4,})['\"]"
)


# Semantic Python AST SAST & Data Science rules
AST_RULE_DOCS: Dict[str, Dict[str, str]] = {
    "AST-SQL-INJECTION": {
        "category": "SAST_DS",
        "severity": "CRITICAL",
        "method": "Python AST",
        "title": "Risco de injeção de SQL (query montada com f-string / + / .format)",
        "title_en": "SQL injection risk (query built via f-string, concatenation, or .format)",
        "plain_why": "A IA concatenou texto direto dentro do comando SQL. Se um usuario digitar aspas ou comandos maliciosos num formulario, ele pode ler ou apagar todo o seu banco de dados.",
        "plain_why_en": "User input is interpolated straight into a SQL command string. Attackers can manipulate query syntax to leak or destroy database tables.",
        "how_to_fix": "Sempre passe variaveis usando parametros preparados (?, %s ou :param) em vez de f-strings ou soma de strings.",
        "how_to_fix_en": "Always bind values with parameterized placeholders (?, %s, or :param) instead of string formatting.",
        "fix_example": "cursor.execute('SELECT * FROM usuarios WHERE email = %s', (email_usuario,))",
    },
    "AST-UNSAFE-PICKLE": {
        "category": "SAST_DS",
        "severity": "HIGH",
        "method": "Python AST",
        "title": "Desserialização insegura de modelo ou dados (pickle / joblib / torch.load)",
        "title_en": "Unsafe model or data deserialization (pickle / joblib / torch.load)",
        "plain_why": "Em Data Science, arquivos .pkl ou pickle.loads() executam codigo Python oculto no momento da leitura. Carregar um arquivo alterado permite invasao remota total do servidor.",
        "plain_why_en": "Loading .pkl files with pickle or joblib executes embedded Python bytecode on read, creating a Remote Code Execution vector.",
        "how_to_fix": "Para tabelas use Parquet/JSON; para modelos prefira ONNX ou Safetensors, ou passe weights_only=True no PyTorch. Nunca carregue .pkl de fonte externa.",
        "how_to_fix_en": "Use Parquet/JSON for datasets, ONNX or Safetensors for ML weights, or pass weights_only=True in torch.load().",
        "fix_example": "# Prefira formatos seguros:\ndf = pd.read_parquet('dados.parquet')\n# PyTorch:\ntorch.load('modelo.pt', weights_only=True)",
    },
    "AST-UNSAFE-YAML": {
        "category": "SAST_DS",
        "severity": "HIGH",
        "method": "Python AST",
        "title": "yaml.load() sem SafeLoader permite execução de código arbitrário",
        "title_en": "yaml.load() without SafeLoader permits arbitrary code execution",
        "plain_why": "A função padrão yaml.load() consegue instanciar classes Python arbitrárias contidas em um arquivo .yml adulterado.",
        "plain_why_en": "Standard yaml.load() deserializes arbitrary Python objects from crafted YAML files, letting attackers run system code.",
        "how_to_fix": "Substitua yaml.load(...) por yaml.safe_load(...) ou informe Loader=yaml.SafeLoader.",
        "how_to_fix_en": "Replace yaml.load(...) with yaml.safe_load(...) or pass Loader=yaml.SafeLoader explicitly.",
        "fix_example": "with open('config.yml') as f:\n    cfg = yaml.safe_load(f)",
    },
    "AST-CODE-EXEC": {
        "category": "SAST_DS",
        "severity": "CRITICAL",
        "method": "Python AST",
        "title": "Execução dinâmica perigosa (eval / exec / os.system / shell=True)",
        "title_en": "Dangerous dynamic execution (eval / exec / os.system / shell=True)",
        "plain_why": "Permite executar qualquer comando do sistema operacional ou código Python em texto livre. É a porta número 1 para invasão de servidores quando recebe entrada do usuário.",
        "plain_why_en": "Evaluates raw strings as Python code or shell commands, allowing full server takeover if untrusted input reaches this call.",
        "how_to_fix": "Para interpretar textos ou dicionarios use json.loads() ou ast.literal_eval(). Em subprocess, passe lista de argumentos sem shell=True.",
        "how_to_fix_en": "Parse structured strings with json.loads() or ast.literal_eval(), and pass argument lists to subprocess without shell=True.",
        "fix_example": "import ast, subprocess\ndados = ast.literal_eval(texto)\nsubprocess.run(['python', 'script.py'], shell=False, check=True)",
    },
    "AST-DEBUG-TRUE": {
        "category": "EXPOSED_DATA",
        "severity": "HIGH",
        "method": "Python AST",
        "title": "Modo debug=True ativado na aplicação web",
        "title_en": "Web framework debug=True enabled in application code",
        "plain_why": "Em Flask/FastAPI, deixar debug=True no servidor expõe mensagens detalhadas de erro, caminhos internos e, no Werkzeug, pode liberar um console interativo Python no navegador.",
        "plain_why_en": "Running Flask or web servers with debug=True leaks stack traces, local file paths, and can expose Werkzeug interactive debugging.",
        "how_to_fix": "Desative debug=True em produção ou controle via variável de ambiente booleana desligada por padrão.",
        "how_to_fix_en": "Set debug=False for production or control it strictly with a default-false environment flag.",
        "fix_example": "debug_mode = os.getenv('APP_DEBUG', 'false').lower() == 'true'\napp.run(debug=debug_mode)",
    },
    "AST-SSL-VERIFY-FALSE": {
        "category": "SAST_DS",
        "severity": "HIGH",
        "method": "Python AST",
        "title": "Verificação de certificado SSL desativada (verify=False)",
        "title_en": "TLS/SSL certificate verification disabled (verify=False)",
        "plain_why": "Desligar verify=False aceita certificados falsos na rede, expondo senhas e tokens trafegados a ataques de interceptação (Man-in-the-Middle).",
        "plain_why_en": "Disabling TLS verification allows spoofed certificates on the network, exposing tokens and API payloads to MitM attacks.",
        "how_to_fix": "Remova verify=False ou aponte o caminho correto do certificado confiável.",
        "how_to_fix_en": "Remove verify=False or point requests to a valid trusted CA bundle path.",
        "fix_example": "resp = requests.get('https://api.exemplo.com', timeout=15)",
    },
    "AST-HARDCODED-SECRET": {
        "category": "SECRETS",
        "severity": "CRITICAL",
        "method": "Python AST",
        "title": "Variável sensível com senha ou chave fixa no código Python",
        "title_en": "Sensitive credential variable assigned a hardcoded string literal",
        "plain_why": "A variável possui nome de credencial (password, api_key, secret_key, token) com valor literal digitado no código-fonte que irá para o Git.",
        "plain_why_en": "A variable named as a credential holds a literal string in code that can easily be committed to source control.",
        "how_to_fix": "Mova o segredo para o arquivo .env (listado no .gitignore) e leia via os.getenv().",
        "how_to_fix_en": "Move the secret into a protected .env file and load it via os.getenv().",
        "fix_example": "import os\nSECRET_KEY = os.getenv('SECRET_KEY')",
    },
    "NB-SAVED-OUTPUTS": {
        "category": "SAST_DS",
        "severity": "LOW",
        "method": "Jupyter JSON",
        "title": "Notebook Jupyter salvo com saídas (outputs) de execução visíveis",
        "title_en": "Jupyter Notebook saved with cell outputs intact",
        "plain_why": "Cientistas de dados frequentemente dão print(df.head()) ou print(token) e salvam o .ipynb. Os outputs ficam gravados em JSON e sobem para o Git expondo dados reais ou caminhos locais.",
        "plain_why_en": "Notebook outputs are stored inside the .ipynb JSON file and frequently leak customer sample rows, tokens, or local tracebacks on Git.",
        "how_to_fix": "Antes de dar commit, limpe todas as saídas das células (Clear All Outputs) ou use nbstripout no pre-commit.",
        "how_to_fix_en": "Clear all cell outputs before committing or automate cleanup with nbstripout.",
        "fix_example": "jupyter nbconvert --clear-output --inplace analise.ipynb",
    },
}

# Supplementary engine checks (filesystem, .gitignore, runtime/PyPI/OSV) documented in /testes
EXTRA_CATALOG_TESTS: List[Dict[str, str]] = [
    {
        "id": "SEC-GENERIC-LITERAL",
        "category": "SECRETS",
        "severity": "HIGH",
        "method": "Regex",
        "title": "Atribuição genérica de senha ou token em texto (.py, .js, .yml, .env)",
        "title_en": "Generic credential literal assignment across code or config files",
        "plain_why": "Identifica variáveis como password, senha, api_key ou vps_root_password com valores literais reais fora de variáveis de ambiente.",
        "plain_why_en": "Catches literal credentials assigned to sensitive variable names across Python, JavaScript, YAML, and environment files.",
        "how_to_fix": "Substitua valores fixos por leitura de ambiente (os.getenv / process.env).",
        "how_to_fix_en": "Replace literal secrets with environment variable lookups.",
    },
    {
        "id": "EXP-DB-IN-PUBLIC-DIR",
        "category": "EXPOSED_DATA",
        "severity": "CRITICAL",
        "method": "Filesystem",
        "title": "Banco de dados ou chave privada dentro de pasta pública web",
        "title_en": "Database file or private key stored inside a public web directory",
        "plain_why": "Bancos (.sqlite, .db, .duckdb) ou chaves (.pem, .key) colocados dentro de static/, public/, htdocs/ ou dist/ ficam acessíveis para download direto pela URL.",
        "plain_why_en": "Databases or keys placed under static/, public/, htdocs/, or dist/ can be downloaded directly via public HTTP URLs.",
        "how_to_fix": "Mova arquivos sensíveis para fora das pastas públicas e bloqueie as extensões no .gitignore.",
        "how_to_fix_en": "Move databases and keys outside public static directories and ignore them in .gitignore.",
    },
    {
        "id": "EXP-UNPROTECTED-DB-FILE",
        "category": "EXPOSED_DATA",
        "severity": "HIGH",
        "method": "Filesystem + Git",
        "title": "Banco de dados ou chave local não coberto pelo .gitignore",
        "title_en": "Local database or key file omitted from .gitignore",
        "plain_why": "Arquivos locais .sqlite, .db, .duckdb ou .pem soltos na pasta serão incluídos no próximo git push se o .gitignore não bloqueá-los.",
        "plain_why_en": "Local database or key files on disk will be staged on git add if their extensions are missing from .gitignore.",
        "how_to_fix": "Inclua as extensões no .gitignore usando o botão automático.",
        "how_to_fix_en": "Add those extensions to .gitignore or run the one-click .gitignore fix.",
    },
    {
        "id": "EXP-ENV-UNPROTECTED",
        "category": "EXPOSED_DATA",
        "severity": "CRITICAL",
        "method": "Filesystem + Git",
        "title": "Arquivo .env real presente sem proteção no .gitignore",
        "title_en": "Active .env credentials file unprotected by .gitignore",
        "plain_why": "O arquivo .env concentra todas as senhas do projeto; sem bloqueio no .gitignore ele sobe para o GitHub no primeiro commit.",
        "plain_why_en": "The .env file holds live secrets; without a .gitignore rule, the next git push publishes every credential.",
        "how_to_fix": "Adicione .env e .env.* ao .gitignore imediatamente.",
        "how_to_fix_en": "Add .env and .env.* to .gitignore immediately.",
    },
    {
        "id": "GIT-NO-GITIGNORE",
        "category": "GIT_HYGIENE",
        "severity": "HIGH",
        "method": "Git Audit",
        "title": "Ausência total de arquivo .gitignore na raiz do projeto",
        "title_en": "Missing .gitignore file at repository root",
        "plain_why": "Sem .gitignore, o Git envia arquivos de senhas, caches e bancos locais para o repositório remoto.",
        "plain_why_en": "Without .gitignore, Git tracks environment files, local databases, and temporary artifacts by default.",
        "how_to_fix": "Crie e blinde o .gitignore na aba Proteção Git.",
        "how_to_fix_en": "Create and harden .gitignore using the automatic protection action.",
    },
    {
        "id": "GIT-INCOMPLETE-IGNORE",
        "category": "GIT_HYGIENE",
        "severity": "HIGH",
        "method": "Git Audit",
        "title": "Arquivo .gitignore existente não cobre padrões críticos",
        "title_en": "Existing .gitignore misses critical security patterns",
        "plain_why": "Um .gitignore padrão incompleto costuma esquecer .env.*, *.sqlite, *.duckdb ou *.pkl.",
        "plain_why_en": "Incomplete .gitignore templates frequently leave out .env.*, *.sqlite, *.duckdb, or *.pkl files.",
        "how_to_fix": "Execute a blindagem automática para acrescentar apenas as regras faltantes.",
        "how_to_fix_en": "Run the automatic .gitignore fix to append only missing security patterns.",
    },
    {
        "id": "GIT-TRACKED-SECRET-FILE",
        "category": "GIT_HYGIENE",
        "severity": "CRITICAL",
        "method": "git ls-files",
        "title": "Arquivo sensível já rastreado no índice do Git",
        "title_en": "Sensitive file already tracked in the Git index",
        "plain_why": "Alterar o .gitignore depois de dar git add não remove um arquivo que já entrou no índice; o Git continua versionando alterações nele.",
        "plain_why_en": "Adding a pattern to .gitignore does not untrack files already committed; Git continues shipping updates to them.",
        "how_to_fix": "Execute git rm --cached <arquivo> e rotacione todas as credenciais expostas.",
        "how_to_fix_en": "Run git rm --cached <file> and rotate any exposed secrets immediately.",
    },
    {
        "id": "ENV-PYTHON-EOL",
        "category": "ENVIRONMENT",
        "severity": "MEDIUM",
        "method": "endoflife.date API",
        "title": "Comparação da versão do Python instalada vs lançamentos oficiais e fim de suporte",
        "title_en": "Installed Python version check against official releases and EOL date",
        "plain_why": "Versões antigas de Python deixam de receber correções de segurança críticas e ficam incompatíveis com bibliotecas modernas.",
        "plain_why_en": "Outdated or end-of-life Python series stop receiving security patches and fall behind current libraries.",
        "how_to_fix": "Use o comando conda install ou winget na aba de ambiente e módulos para atualizar.",
        "how_to_fix_en": "Upgrade Python using the conda or winget command shown in the environment and modules tab.",
    },
    {
        "id": "ENV-PYPI-HALLUCINATED",
        "category": "ENVIRONMENT",
        "severity": "CRITICAL",
        "method": "PyPI JSON API",
        "title": "Detecção de pacotes alucinados por IA (HTTP 404 no PyPI)",
        "title_en": "Detection of AI-hallucinated package names (PyPI HTTP 404)",
        "plain_why": "Modelos de IA às vezes inventam nomes de pacotes inexistentes; invasores registram esses nomes no PyPI com malware (ataque slopsquatting).",
        "plain_why_en": "LLMs sometimes invent non-existent package names that attackers register on PyPI to ship malware (slopsquatting).",
        "how_to_fix": "Remova imediatamente o pacote do requirements.txt e confira a grafia oficial da biblioteca.",
        "how_to_fix_en": "Remove unverified package names from requirements.txt and confirm official spellings on PyPI.",
    },
    {
        "id": "ENV-OSV-CVES",
        "category": "ENVIRONMENT",
        "severity": "HIGH",
        "method": "Google OSV.dev API",
        "title": "Auditoria em lote de CVEs e vulnerabilidades conhecidas nas dependências",
        "title_en": "Batch CVE / GHSA / PYSEC vulnerability scan against Google OSV.dev",
        "plain_why": "Mesmo pacotes legítimos antigos possuem falhas públicas conhecidas facilmente exploráveis.",
        "plain_why_en": "Older versions of popular Python libraries often carry documented CVEs with known exploit paths.",
        "how_to_fix": "Clique em Atualizar na linha do pacote afetado após confirmar o aviso de versão.",
        "how_to_fix_en": "Upgrade affected libraries directly after reviewing the version confirmation dialog.",
    },
]

# Optional installable test modules available from "+ Adicionar mais testes"
OPTIONAL_MODULES: Dict[str, Dict[str, Any]] = {
    "mod_lgpd_pii": {
        "id": "mod_lgpd_pii",
        "category": "PRIVACY_LGPD",
        "name": "Módulo de privacidade e LGPD (dados pessoais)",
        "name_en": "Privacy and personal data (PII) module",
        "description": "Procura CPF fixo e e-mails pessoais reais deixados em scripts de teste ou código.",
        "description_en": "Detects literal Brazilian CPF numbers and personal emails left inside test scripts or fixtures.",
        "rules": [
            {
                "id": "LGPD-CPF-LITERAL",
                "category": "PRIVACY_LGPD",
                "severity": "HIGH",
                "method": "Regex (LGPD)",
                "title": "CPF em formato literal encontrado no código ou fixture",
                "title_en": "Literal CPF taxpayer number found in source code",
                "pattern": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
                "mask_match": True,
                "plain_why": "Subir CPFs reais de clientes ou pessoas para o Git viola a LGPD e expõe dados pessoais sensíveis.",
                "plain_why_en": "Committing real tax IDs or citizen identifiers into Git violates data privacy laws and leaks personal records.",
                "how_to_fix": "Substitua dados reais por geradores sintéticos (ex.: biblioteca Faker) ou mascare os valores.",
                "how_to_fix_en": "Replace real records with synthetic mock generators such as Faker or anonymized IDs.",
                "fix_example": "from faker import Faker\ncpf_teste = Faker('pt_BR').cpf()",
            },
            {
                "id": "LGPD-PERSONAL-EMAIL",
                "category": "PRIVACY_LGPD",
                "severity": "LOW",
                "method": "Regex (LGPD)",
                "title": "E-mail pessoal chumbado no código-fonte",
                "title_en": "Hardcoded personal email address in source file",
                "pattern": re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:gmail|hotmail|outlook|yahoo|icloud|uol|bol)\.com(?:\.br)?\b", re.IGNORECASE),
                "mask_match": True,
                "plain_why": "Endereços pessoais salvos em código público viram alvo de spam, phishing e exposição de identidade.",
                "plain_why_en": "Personal email literals in public repos invite phishing, spam harvesting, and unwanted identity exposure.",
                "how_to_fix": "Troque por variáveis de ambiente ou use endereços fictícios @exemplo.local em testes.",
                "how_to_fix_en": "Load contact emails from environment config or use RFC dummy @example.com addresses in tests.",
                "fix_example": "admin_email = os.getenv('ADMIN_EMAIL', 'contato@exemplo.local')",
            },
        ],
    },
    "mod_docker_infra": {
        "id": "mod_docker_infra",
        "category": "DOCKER_INFRA",
        "name": "Módulo de Docker e containers",
        "name_en": "Docker and containers hardening module",
        "description": "Verifica se há containers rodando como root, senhas em ENV de Dockerfile ou portas de banco expostas em 0.0.0.0.",
        "description_en": "Checks for containers running as root, secrets in Dockerfile ENV lines, and database ports bound to 0.0.0.0.",
        "rules": [
            {
                "id": "DOCKER-ROOT-USER",
                "category": "DOCKER_INFRA",
                "severity": "MEDIUM",
                "method": "Regex (Docker)",
                "title": "Container configurado explicitamente com usuário root",
                "title_en": "Container explicitly sets USER root",
                "pattern": re.compile(r"^\s*USER\s+(?:root|0)\b", re.IGNORECASE),
                "mask_match": False,
                "plain_why": "Se um invasor explorar uma falha na aplicação dentro do container rodando como root, o risco de escape para o servidor aumenta.",
                "plain_why_en": "Running application processes as root inside containers raises privilege escalation impact if compromised.",
                "how_to_fix": "Crie e ative um usuário sem privilégios administrativos no Dockerfile antes do CMD.",
                "how_to_fix_en": "Create and switch to a non-root user in your Dockerfile prior to ENTRYPOINT/CMD.",
                "fix_example": "RUN useradd -m appuser\nUSER appuser",
            },
            {
                "id": "DOCKER-ENV-SECRET",
                "category": "DOCKER_INFRA",
                "severity": "CRITICAL",
                "method": "Regex (Docker)",
                "title": "Senha ou token gravado em instrução ENV/ARG de container",
                "title_en": "Secret password or key written inside container ENV/ARG",
                "pattern": re.compile(r"^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*[= ]\s*\S+", re.IGNORECASE),
                "mask_match": True,
                "plain_why": "Valores colocados em ENV ou ARG no Dockerfile ficam gravados em texto claro nas camadas da imagem Docker.",
                "plain_why_en": "Credentials defined in Dockerfile ENV or ARG persist in plain text inside image history layers.",
                "how_to_fix": "Injete segredos apenas em tempo de execução com docker run --env-file ou Docker secrets.",
                "how_to_fix_en": "Pass runtime secrets via --env-file .env or container orchestrator secret mounts.",
                "fix_example": "# Em docker-compose.yml:\nenv_file:\n  - .env",
            },
            {
                "id": "DOCKER-OPEN-DB-PORT",
                "category": "DOCKER_INFRA",
                "severity": "HIGH",
                "method": "Regex (Docker)",
                "title": "Porta de banco de dados publicada para todas as interfaces (0.0.0.0)",
                "title_en": "Database port exposed to all network interfaces (0.0.0.0)",
                "pattern": re.compile(r"(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379):(?:5432|3306|27017|6379)"),
                "mask_match": False,
                "plain_why": "Publicar portas de Postgres, MySQL, Mongo ou Redis diretamente no host sem 127.0.0.1 expõe o banco à internet pública.",
                "plain_why_en": "Binding Postgres, MySQL, Mongo, or Redis without 127.0.0.1 can expose the database port directly on public interfaces.",
                "how_to_fix": "Restrinja o mapeamento no Compose para 127.0.0.1 ou comunique apenas pela rede interna do Docker.",
                "how_to_fix_en": "Bind ports to 127.0.0.1:5432:5432 or keep database services only on an internal Docker network.",
                "fix_example": "ports:\n  - \"127.0.0.1:5432:5432\"",
            },
        ],
    },
    "mod_cloud_ssh": {
        "id": "mod_cloud_ssh",
        "category": "CLOUD_SSH",
        "name": "Módulo de cloud, buckets e SSH",
        "name_en": "Cloud buckets and SSH hardening module",
        "description": "Detecta senhas passadas em linha de comando SSH (sshpass) e permissões públicas de buckets.",
        "description_en": "Detects inline SSH passwords (sshpass) and overly permissive public storage bucket ACLs.",
        "rules": [
            {
                "id": "CLOUD-SSHPASS-LITERAL",
                "category": "CLOUD_SSH",
                "severity": "CRITICAL",
                "method": "Regex (Cloud/SSH)",
                "title": "Senha exposta em comando sshpass ou script de deploy",
                "title_en": "Plaintext password passed to sshpass deployment command",
                "pattern": re.compile(r"\bsshpass\s+-p\s+['\"]?[^\s'\"]{3,}", re.IGNORECASE),
                "mask_match": True,
                "plain_why": "Senhas em comandos sshpass ficam visíveis no código, logs de terminal e histórico de processos do sistema.",
                "plain_why_en": "Passwords passed to sshpass -p leak into source scripts, CI logs, and host process listings.",
                "how_to_fix": "Configure autenticação por chave SSH ou use sshpass -e lendo da variável SSHPASS.",
                "how_to_fix_en": "Authenticate using SSH key pairs or load credentials strictly via SSHPASS environment variable.",
                "fix_example": "ssh -i ~/.ssh/deploy_key usuario@servidor",
            },
            {
                "id": "CLOUD-PUBLIC-ACL",
                "category": "CLOUD_SSH",
                "severity": "HIGH",
                "method": "Regex (Cloud/SSH)",
                "title": "Permissão pública aberta em armazenamento cloud (public-read)",
                "title_en": "Public storage ACL configured (public-read / allUsers)",
                "pattern": re.compile(r"(?:public-read(?:-write)?|allUsers|AllAuthenticatedUsers)", re.IGNORECASE),
                "mask_match": False,
                "plain_why": "Buckets S3 ou Cloud Storage com public-read permitem que qualquer pessoa baixe arquivos internos sem autenticação.",
                "plain_why_en": "Cloud storage objects marked public-read or allUsers allow unauthenticated downloads across the internet.",
                "how_to_fix": "Mude a ACL para private e gere URLs assinadas temporárias apenas quando necessário.",
                "how_to_fix_en": "Set ACL to private and issue short-lived pre-signed URLs for authorized downloads.",
                "fix_example": "s3.put_object(Bucket=bucket, Key=key, Body=data, ACL='private')",
            },
        ],
    },
}


def get_active_regex_rules(prefs: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Compile built-in rules plus enabled optional modules and user custom rules."""
    prefs = prefs or {}
    disabled = set(prefs.get("disabled_rules") or [])
    installed_mods = set(prefs.get("installed_modules") or [])

    active: List[Dict[str, Any]] = []
    for r in REGEX_RULES:
        if r["id"] not in disabled:
            active.append(r)

    for mod_id, mod_info in OPTIONAL_MODULES.items():
        if mod_id in installed_mods:
            for r in mod_info["rules"]:
                if r["id"] not in disabled:
                    active.append(r)

    for cr in prefs.get("custom_rules") or []:
        if cr.get("id") in disabled:
            continue
        try:
            compiled = re.compile(cr["pattern"])
        except re.error:
            continue
        active.append({
            "id": cr["id"],
            "category": cr.get("category", "DEPLOY_TRAPS"),
            "severity": cr.get("severity", "MEDIUM"),
            "method": cr.get("method", "Regex customizado"),
            "title": cr.get("title", cr["id"]),
            "title_en": cr.get("title_en", cr.get("title", cr["id"])),
            "pattern": compiled,
            "mask_match": False,
            "plain_why": cr.get("plain_why", ""),
            "plain_why_en": cr.get("plain_why_en", cr.get("plain_why", "")),
            "how_to_fix": cr.get("how_to_fix", ""),
            "how_to_fix_en": cr.get("how_to_fix_en", cr.get("how_to_fix", "")),
            "fix_example": cr.get("fix_example", ""),
        })
    return active


def build_finding(
    rule_id: str,
    file_path: str,
    line: int,
    snippet: str,
    category: str,
    severity: str,
    title: str,
    plain_why: str,
    how_to_fix: str,
    fix_example: str = "",
    lang: str = "pt",
) -> Dict[str, Any]:
    """Build a standardized finding payload localized to PT-BR or EN."""
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "line": line,
        "snippet": snippet.strip()[:220],
        "category": category,
        "category_label": get_category_label(category, lang),
        "severity": severity,
        "title": title,
        "plain_why": plain_why,
        "how_to_fix": how_to_fix,
        "fix_example": fix_example,
    }


def get_all_tests_documentation(lang: str = "pt", prefs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Return all security rules grouped by thematic blocks, module state, and scoring criteria."""
    code = normalize_lang(lang)
    is_en = code == "en"
    prefs = prefs or {}
    disabled = set(prefs.get("disabled_rules") or [])
    installed_mods = set(prefs.get("installed_modules") or [])
    tests_list: List[Dict[str, Any]] = []

    def append_test_entry(entry: Dict[str, Any], rule_id: str, method_default: str, module_id: str = "", is_custom: bool = False):
        tests_list.append({
            "id": rule_id,
            "category": entry["category"],
            "category_label": get_category_label(entry["category"], code),
            "severity": entry["severity"],
            "method": entry.get("method", method_default),
            "title": pick_lang_text(entry, "title", code),
            "plain_why": pick_lang_text(entry, "plain_why", code),
            "how_to_fix": pick_lang_text(entry, "how_to_fix", code),
            "fix_example": entry.get("fix_example", ""),
            "enabled": rule_id not in disabled,
            "module_id": module_id,
            "is_custom": is_custom,
        })

    for rule in REGEX_RULES:
        append_test_entry(rule, rule["id"], "Regex")

    for rule_id, meta in AST_RULE_DOCS.items():
        append_test_entry(meta, rule_id, "Python AST")

    for extra in EXTRA_CATALOG_TESTS:
        append_test_entry(extra, extra["id"], extra.get("method", "Audit"))

    for mod_id, mod_info in OPTIONAL_MODULES.items():
        if mod_id in installed_mods:
            for r in mod_info["rules"]:
                append_test_entry(r, r["id"], r.get("method", "Módulo extra"), module_id=mod_id)

    for cr in prefs.get("custom_rules") or []:
        append_test_entry(cr, cr["id"], cr.get("method", "Regex customizado"), is_custom=True)

    tests_list.sort(key=lambda t: (SEVERITY_ORDER.get(t["severity"], 99), t["category"], t["id"]))

    # Group tests into thematic blocks for structured navigation.
    block_order = [
        "SECRETS",
        "EXPOSED_DATA",
        "DEPLOY_TRAPS",
        "SAST_DS",
        "GIT_HYGIENE",
        "ENVIRONMENT",
        "PRIVACY_LGPD",
        "DOCKER_INFRA",
        "CLOUD_SSH",
    ]
    blocks_map: Dict[str, List[Dict[str, Any]]] = {}
    for item in tests_list:
        blocks_map.setdefault(item["category"], []).append(item)

    blocks = []
    for cat_key in block_order:
        cat_items = blocks_map.get(cat_key)
        if not cat_items:
            continue
        blocks.append({
            "category": cat_key,
            "label": get_category_label(cat_key, code),
            "active_count": sum(1 for x in cat_items if x["enabled"]),
            "total_count": len(cat_items),
            "tests": cat_items,
        })

    optional_modules_meta = [
        {
            "id": mod_id,
            "category": mod["category"],
            "category_label": get_category_label(mod["category"], code),
            "name": mod["name_en"] if is_en else mod["name"],
            "description": mod["description_en"] if is_en else mod["description"],
            "rule_count": len(mod["rules"]),
            "installed": mod_id in installed_mods,
        }
        for mod_id, mod in OPTIONAL_MODULES.items()
    ]

    if is_en:
        scoring_info = {
            "formula": "Score = max(0, 100 - sum(severity_penalty_per_finding))",
            "grades": [
                {"grade": "A", "range": "90 - 100 (0 critical)", "meaning": "Ready to publish"},
                {"grade": "B", "range": "75 - 89 (0 critical)", "meaning": "Good, minor adjustments suggested"},
                {"grade": "C", "range": "55 - 74", "meaning": "Attention needed before deploy"},
                {"grade": "D", "range": "35 - 54", "meaning": "Elevated risk - fix before push"},
                {"grade": "F", "range": "0 - 34", "meaning": "Blocked: critical exposure risk"},
            ],
        }
    else:
        scoring_info = {
            "formula": "Score = max(0, 100 - soma(peso_da_severidade_por_achado))",
            "grades": [
                {"grade": "A", "range": "90 - 100 (0 críticos)", "meaning": "Pronto para publicar"},
                {"grade": "B", "range": "75 - 89 (0 críticos)", "meaning": "Bom, com ajustes menores recomendados"},
                {"grade": "C", "range": "55 - 74", "meaning": "Atenção necessária antes do deploy"},
                {"grade": "D", "range": "35 - 54", "meaning": "Risco elevado - corrija antes de subir"},
                {"grade": "F", "range": "0 - 34", "meaning": "Bloqueado: risco crítico de vazamento"},
            ],
        }

    return {
        "status": "success",
        "lang": code,
        "total_tests": len(tests_list),
        "enabled_tests": sum(1 for t in tests_list if t["enabled"]),
        "disabled_tests": sum(1 for t in tests_list if not t["enabled"]),
        "severity_weights": SEVERITY_WEIGHTS,
        "scoring": scoring_info,
        "blocks": blocks,
        "tests": tests_list,
        "optional_modules": optional_modules_meta,
        "github_repo_url": prefs.get("github_repo_url", ""),
    }
