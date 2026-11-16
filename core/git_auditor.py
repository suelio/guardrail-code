"""Audit .gitignore coverage and detect sensitive files tracked by Git."""

import os
import subprocess
from typing import Dict, Any, List, Tuple
from .rules_catalog import build_finding, normalize_lang

REQUIRED_GITIGNORE_RULES: List[Tuple[str, str, str, str]] = [
    (".env", "Variaveis de ambiente e senhas (.env)", "Environment variables and secrets (.env)", "CRITICAL"),
    (".env.*", "Variacoes de ambiente (.env.local, .env.prod)", "Environment variants (.env.local, .env.prod)", "CRITICAL"),
    ("*.pem", "Chaves privadas PEM", "PEM private cryptographic keys", "CRITICAL"),
    ("*.key", "Arquivos de chave criptografica", "Secret key files", "CRITICAL"),
    ("*.sqlite", "Bancos locais SQLite", "Local SQLite databases", "HIGH"),
    ("*.sqlite3", "Bancos locais SQLite3", "Local SQLite3 databases", "HIGH"),
    ("*.db", "Arquivos genericos de banco de dados", "Generic local database files", "HIGH"),
    ("*.duckdb", "Bancos analiticos DuckDB", "Analytical DuckDB databases", "HIGH"),
    ("*.pkl", "Modelos serializados Pickle (risco RCE/dados)", "Serialized Pickle models (RCE/data risk)", "MEDIUM"),
    ("__pycache__/", "Cache compilado Python", "Python bytecode cache", "LOW"),
    (".ipynb_checkpoints/", "Checkpoints temporarios Jupyter", "Temporary Jupyter checkpoints", "LOW"),
]

SENSITIVE_EXTENSIONS = (".env", ".pem", ".key", ".sqlite", ".sqlite3", ".db", ".duckdb", ".pkl")


def _normalize_pattern(line: str) -> str:
    return line.strip().lstrip("/").rstrip("/")


def _is_pattern_covered(required_pat: str, gitignore_lines: List[str]) -> bool:
    req_norm = _normalize_pattern(required_pat)
    for raw in gitignore_lines:
        clean = raw.strip()
        if not clean or clean.startswith("#"):
            continue
        norm = _normalize_pattern(clean)
        if norm == req_norm:
            return True
        if req_norm.startswith(".") and norm == req_norm:
            return True
        if req_norm == ".env.*" and norm in (".env.*", "*.env", ".env*"):
            return True
    return False


def audit_git_protection(target_dir: str, lang: str = "pt") -> Dict[str, Any]:
    """Check .gitignore rules and run 'git ls-files' to catch tracked sensitive files."""
    code = normalize_lang(lang)
    is_en = code == "en"
    is_git_repo = os.path.isdir(os.path.join(target_dir, ".git"))
    gitignore_path = os.path.join(target_dir, ".gitignore")
    has_gitignore = os.path.isfile(gitignore_path)

    gitignore_lines: List[str] = []
    if has_gitignore:
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as f:
            gitignore_lines = f.read().splitlines()

    checklist = []
    missing_patterns = []
    for pattern, desc_pt, desc_en, sev in REQUIRED_GITIGNORE_RULES:
        covered = _is_pattern_covered(pattern, gitignore_lines)
        checklist.append({
            "pattern": pattern,
            "description": desc_en if is_en else desc_pt,
            "severity": sev,
            "covered": covered,
        })
        if not covered:
            missing_patterns.append(pattern)

    tracked_sensitive_files: List[str] = []
    if is_git_repo:
        try:
            proc = subprocess.run(
                ["git", "-C", target_dir, "ls-files"],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if proc.returncode == 0:
                for rel_file in proc.stdout.splitlines():
                    low = rel_file.strip().lower()
                    base = os.path.basename(low)
                    if (
                        base == ".env"
                        or base.startswith(".env.")
                        or low.endswith((".pem", ".key", ".sqlite", ".sqlite3", ".db", ".duckdb", ".pkl", ".p12"))
                    ):
                        tracked_sensitive_files.append(rel_file.strip())
        except Exception:
            pass

    findings: List[Dict[str, Any]] = []
    if not has_gitignore:
        findings.append(
            build_finding(
                rule_id="GIT-NO-GITIGNORE",
                file_path="(project root)" if is_en else "(raiz do projeto)",
                line=1,
                snippet="Missing .gitignore file" if is_en else "Arquivo .gitignore ausente",
                category="GIT_HYGIENE",
                severity="HIGH",
                title="Project has no .gitignore file" if is_en else "Projeto sem arquivo .gitignore",
                plain_why=(
                    "Without a .gitignore file, Git pushes .env passwords, local SQLite databases, and cache files directly to your public repository."
                    if is_en else
                    "Sem .gitignore, o Git envia arquivos .env com senhas, bancos SQLite locais e lixo temporario para o repositorio publico."
                ),
                how_to_fix=(
                    "Click 'Fix & Harden .gitignore Automatically' in the Git Protection tab."
                    if is_en else
                    "Clique no botao 'Corrigir e Blindar .gitignore Automaticamente' na aba Git & .gitignore."
                ),
                fix_example=".env\n.env.*\n*.sqlite\n*.db\n*.duckdb\n*.pkl\n__pycache__/",
                lang=code,
            )
        )
    else:
        critical_missing = [c["pattern"] for c in checklist if not c["covered"] and c["severity"] in ("CRITICAL", "HIGH")]
        if critical_missing:
            findings.append(
                build_finding(
                    rule_id="GIT-INCOMPLETE-IGNORE",
                    file_path=".gitignore",
                    line=1,
                    snippet=("Missing patterns: " if is_en else "Faltando proteger: ") + ", ".join(critical_missing),
                    category="GIT_HYGIENE",
                    severity="HIGH",
                    title=(
                        f"Incomplete .gitignore ({len(critical_missing)} critical protections missing)"
                        if is_en else
                        f".gitignore incompleto ({len(critical_missing)} protecoes criticas ausentes)"
                    ),
                    plain_why=(
                        "Although .gitignore exists, it does not block critical files such as .env credentials or local databases (.sqlite/.db/.duckdb)."
                        if is_en else
                        "Mesmo existindo um .gitignore, ele nao esta bloqueando arquivos criticos como senhas (.env) ou bancos locais (.sqlite/.db/.duckdb)."
                    ),
                    how_to_fix=(
                        "Append the missing patterns to .gitignore before committing or apply the one-click fix."
                        if is_en else
                        "Adicione os padroes ausentes no .gitignore antes do proximo commit ou use a correcao em 1 clique."
                    ),
                    fix_example="\n".join(critical_missing),
                    lang=code,
                )
            )

    for tracked in tracked_sensitive_files:
        findings.append(
            build_finding(
                rule_id="GIT-TRACKED-SECRET-FILE",
                file_path=tracked,
                line=1,
                snippet=f"git ls-files -> {tracked}",
                category="GIT_HYGIENE",
                severity="CRITICAL",
                title=(
                    f"Sensitive file already tracked by Git: {tracked}"
                    if is_en else
                    f"Arquivo sensivel ja esta rastreado pelo Git: {tracked}"
                ),
                plain_why=(
                    "Even if you add this path to .gitignore later, Git continues pushing changes because the file is already indexed."
                    if is_en else
                    "Mesmo que voce coloque esse nome no .gitignore depois, o Git continua enviando alteracoes porque o arquivo ja foi adicionado ao historico."
                ),
                how_to_fix=(
                    "Untrack it from Git without deleting the local file using 'git rm --cached' and rotate exposed credentials."
                    if is_en else
                    "Remova apenas do rastreamento do Git sem apagar do seu disco usando 'git rm --cached' e rotacione quaisquer senhas contidas nele."
                ),
                fix_example=f'git rm --cached "{tracked}"',
                lang=code,
            )
        )

    return {
        "is_git_repo": is_git_repo,
        "has_gitignore": has_gitignore,
        "gitignore_path": gitignore_path,
        "checklist": checklist,
        "missing_patterns": missing_patterns,
        "tracked_sensitive_files": tracked_sensitive_files,
        "protected_count": sum(1 for c in checklist if c["covered"]),
        "total_rules": len(checklist),
        "findings": findings,
    }


def fix_gitignore(target_dir: str, lang: str = "pt") -> Dict[str, Any]:
    """Safely append missing security patterns to the project .gitignore file."""
    code = normalize_lang(lang)
    is_en = code == "en"
    if not os.path.isdir(target_dir):
        raise FileNotFoundError(
            f"Directory not found: {target_dir}" if is_en else f"Diretorio nao encontrado: {target_dir}"
        )

    audit = audit_git_protection(target_dir, lang=code)
    missing = audit["missing_patterns"]
    gitignore_path = audit["gitignore_path"]

    if not missing:
        return {
            "status": "success",
            "added_patterns": [],
            "message": (
                "Your .gitignore already includes every essential security pattern."
                if is_en else
                "Seu .gitignore ja possui todas as regras essenciais de seguranca."
            ),
            "audit": audit,
        }

    existing_content = ""
    if os.path.isfile(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as f:
            existing_content = f.read()

    section_lines = ["", "# --- Is My Project Exposed?: Secrets, Databases, and Data Science ---"]
    section_lines.extend(missing)
    new_block = "\n".join(section_lines) + "\n"

    updated_content = (existing_content.rstrip() + "\n" + new_block).lstrip("\n")
    with open(gitignore_path, "w", encoding="utf-8") as f:
        f.write(updated_content)

    updated_audit = audit_git_protection(target_dir, lang=code)
    return {
        "status": "success",
        "added_patterns": missing,
        "message": (
            f"Added {len(missing)} security pattern(s) to .gitignore."
            if is_en else
            f"{len(missing)} regra(s) de protecao adicionada(s) ao .gitignore."
        ),
        "audit": updated_audit,
    }
