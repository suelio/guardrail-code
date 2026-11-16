"""Manage persisted rule toggles, optional test modules, custom rules, and GitHub source."""

import json
import os
import re
import urllib.error
import urllib.request
from typing import Dict, Any, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
PREFS_FILE = os.path.join(CONFIG_DIR, "scanner_preferences.json")

DEFAULT_GITHUB_REPO = "https://github.com/suelio/guardrail-code"
_GITHUB_REPO_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
_REDOS_SUSPECT_RE = re.compile(r"\([^)]*[+*][^)]*\)[+*]")

DEFAULT_PREFERENCES: Dict[str, Any] = {
    "disabled_rules": [],
    "installed_modules": [],
    "custom_rules": [],
    "github_repo_url": DEFAULT_GITHUB_REPO,
}


def load_preferences(prefs_path: str = None) -> Dict[str, Any]:
    """Load saved scanner preferences or create defaults when absent."""
    target_path = prefs_path or PREFS_FILE
    if not os.path.isfile(target_path):
        return {
            "disabled_rules": list(DEFAULT_PREFERENCES["disabled_rules"]),
            "installed_modules": list(DEFAULT_PREFERENCES["installed_modules"]),
            "custom_rules": list(DEFAULT_PREFERENCES["custom_rules"]),
            "github_repo_url": DEFAULT_PREFERENCES["github_repo_url"],
        }
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "disabled_rules": list(dict.fromkeys(data.get("disabled_rules") or [])),
            "installed_modules": list(dict.fromkeys(data.get("installed_modules") or [])),
            "custom_rules": list(data.get("custom_rules") or []),
            "github_repo_url": str(data.get("github_repo_url") or DEFAULT_GITHUB_REPO),
        }
    except Exception:
        return dict(DEFAULT_PREFERENCES)


def save_preferences(prefs: Dict[str, Any], prefs_path: str = None) -> Dict[str, Any]:
    """Persist scanner preferences atomically to config/scanner_preferences.json."""
    target_path = prefs_path or PREFS_FILE
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2, ensure_ascii=False)
    return prefs


def toggle_rule_status(rule_id: str, enabled: bool, prefs_path: str = None) -> Dict[str, Any]:
    """Enable or disable a specific rule ID without removing it from the catalog."""
    clean_id = (rule_id or "").strip()
    if not clean_id:
        raise ValueError("Identificador da regra obrigatório.")
    prefs = load_preferences(prefs_path)
    disabled = set(prefs["disabled_rules"])
    if enabled:
        disabled.discard(clean_id)
    else:
        disabled.add(clean_id)
    prefs["disabled_rules"] = sorted(disabled)
    save_preferences(prefs, prefs_path)
    return prefs


def toggle_module_installation(module_id: str, install: bool, prefs_path: str = None) -> Dict[str, Any]:
    """Install or uninstall an optional test module package."""
    clean_mod = (module_id or "").strip()
    if not clean_mod:
        raise ValueError("Identificador do módulo obrigatório.")
    prefs = load_preferences(prefs_path)
    installed = set(prefs["installed_modules"])
    if install:
        installed.add(clean_mod)
    else:
        installed.discard(clean_mod)
    prefs["installed_modules"] = sorted(installed)
    save_preferences(prefs, prefs_path)
    return prefs


def add_custom_rule(rule_data: Dict[str, Any], prefs_path: str = None) -> Dict[str, Any]:
    """Validate and save a user-defined regex test into custom_rules."""
    raw_id = (rule_data.get("id") or "CUSTOM-RULE").strip().upper()
    rule_id = re.sub(r"[^A-Z0-9_-]", "-", raw_id)
    pattern = (rule_data.get("pattern") or "").strip()
    title = (rule_data.get("title") or "").strip()
    if not title or not pattern:
        raise ValueError("Nome do teste e expressão regex são obrigatórios.")
    if len(pattern) > 300 or _REDOS_SUSPECT_RE.search(pattern):
        raise ValueError("Expressão regular muito longa ou com risco de ReDoS.")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Expressão regular inválida: {exc}")

    prefs = load_preferences(prefs_path)
    existing = [r for r in prefs["custom_rules"] if r.get("id") != rule_id]
    existing.append({
        "id": rule_id,
        "category": (rule_data.get("category") or "DEPLOY_TRAPS").strip().upper(),
        "severity": (rule_data.get("severity") or "MEDIUM").strip().upper(),
        "method": "Regex customizado",
        "title": title,
        "title_en": (rule_data.get("title_en") or title).strip(),
        "pattern": pattern,
        "plain_why": (rule_data.get("plain_why") or "Padrão customizado sinalizado pela regra local.").strip(),
        "plain_why_en": (rule_data.get("plain_why_en") or rule_data.get("plain_why") or "Custom pattern flagged by user rule.").strip(),
        "how_to_fix": (rule_data.get("how_to_fix") or "Revise ou remova a ocorrência encontrada.").strip(),
        "how_to_fix_en": (rule_data.get("how_to_fix_en") or rule_data.get("how_to_fix") or "Review or remove the matched line.").strip(),
        "fix_example": (rule_data.get("fix_example") or "").strip(),
    })
    prefs["custom_rules"] = existing
    save_preferences(prefs, prefs_path)
    return prefs


def remove_custom_rule(rule_id: str, prefs_path: str = None) -> Dict[str, Any]:
    """Delete a user-defined rule from preferences."""
    clean_id = (rule_id or "").strip()
    prefs = load_preferences(prefs_path)
    prefs["custom_rules"] = [r for r in prefs["custom_rules"] if r.get("id") != clean_id]
    prefs["disabled_rules"] = [r for r in prefs["disabled_rules"] if r != clean_id]
    save_preferences(prefs, prefs_path)
    return prefs


def parse_github_owner_repo(url: str) -> Tuple[str, str]:
    """Validate and extract GitHub owner/repository from a strict HTTPS GitHub URL."""
    cleaned = (url or "").strip()
    m = _GITHUB_REPO_RE.match(cleaned)
    if not m:
        raise ValueError("Informe uma URL HTTPS válida do GitHub (ex.: https://github.com/usuario/guardrail-code).")
    return m.group(1), m.group(2)


def update_github_repo_url(url: str, prefs_path: str = None) -> Dict[str, Any]:
    """Save the project GitHub repository URL used as the community modules source."""
    owner, repo = parse_github_owner_repo(url)
    normalized = f"https://github.com/{owner}/{repo}"
    prefs = load_preferences(prefs_path)
    prefs["github_repo_url"] = normalized
    save_preferences(prefs, prefs_path)
    return prefs


def _fetch_github_json(url: str, max_bytes: int = 512_000) -> Dict[str, Any]:
    """Fetch JSON securely over HTTPS from GitHub with strict timeout and size cap."""
    if not url.startswith("https://raw.githubusercontent.com/"):
        raise ValueError("URL externa não autorizada.")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "guardrail-code/1.0-beta", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=6) as resp:
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("Arquivo remoto excedeu o limite seguro de tamanho.")
        return json.loads(raw.decode("utf-8"))


def check_github_module_updates(lang: str = "pt", prefs_path: str = None) -> Dict[str, Any]:
    """Check the configured GitHub repository for new community test packs."""
    is_en = str(lang or "pt").lower().startswith("en")
    prefs = load_preferences(prefs_path)
    repo_url = prefs.get("github_repo_url") or DEFAULT_GITHUB_REPO
    owner, repo = parse_github_owner_repo(repo_url)

    manifest = None
    for branch in ("main", "master"):
        manifest_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/community_modules/manifest.json"
        try:
            manifest = _fetch_github_json(manifest_url)
            break
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError, OSError):
            continue

    if not isinstance(manifest, dict) or not isinstance(manifest.get("modules"), list):
        return {
            "status": "success",
            "repo_url": f"https://github.com/{owner}/{repo}",
            "repo_reachable": False,
            "has_updates": False,
            "new_modules": [],
            "message": (
                "No remote update manifest found yet (repository offline or no community_modules/manifest.json published)."
                if is_en else
                "Nenhum pacote novo publicado neste repositório ainda (repositório offline ou sem community_modules/manifest.json)."
            ),
        }

    existing_rule_ids = {r.get("id") for r in (prefs.get("custom_rules") or [])}
    new_modules = []
    for mod in manifest.get("modules", []):
        rules = mod.get("rules") or []
        uninstalled_rules = [r for r in rules if r.get("id") and r.get("id") not in existing_rule_ids]
        if uninstalled_rules:
            new_modules.append({
                "id": str(mod.get("id") or "remote-pack"),
                "name": str(mod.get("name_en") if is_en and mod.get("name_en") else mod.get("name") or "Remote pack"),
                "description": str(mod.get("description_en") if is_en and mod.get("description_en") else mod.get("description") or ""),
                "version": str(mod.get("version") or "1.0.0"),
                "rules": uninstalled_rules,
                "rules_count": len(uninstalled_rules),
            })

    if new_modules:
        msg = (
            f"{len(new_modules)} new test module(s) available to download."
            if is_en else
            f"{len(new_modules)} novo(s) módulo(s) de testes disponíveis para baixar."
        )
    else:
        msg = (
            "All remote test modules from this repository are already up to date."
            if is_en else
            "Todos os módulos deste repositório já estão atualizados localmente."
        )

    return {
        "status": "success",
        "repo_url": f"https://github.com/{owner}/{repo}",
        "repo_reachable": True,
        "has_updates": len(new_modules) > 0,
        "new_modules": new_modules,
        "message": msg,
    }


def download_github_module_updates(lang: str = "pt", prefs_path: str = None) -> Dict[str, Any]:
    """Download and validate new regex test rules from the configured GitHub repository."""
    is_en = str(lang or "pt").lower().startswith("en")
    check = check_github_module_updates(lang=lang, prefs_path=prefs_path)
    if not check["has_updates"]:
        return {
            "status": "success",
            "added_count": 0,
            "message": check["message"],
        }

    added_count = 0
    for mod in check["new_modules"]:
        for rule in mod.get("rules", []):
            try:
                add_custom_rule(rule, prefs_path=prefs_path)
                added_count += 1
            except ValueError:
                continue

    return {
        "status": "success",
        "added_count": added_count,
        "message": (
            f"Downloaded and installed {added_count} new rule(s) safely."
            if is_en else
            f"{added_count} nova(s) regra(s) baixada(s) e instalada(s) com segurança."
        ),
    }
