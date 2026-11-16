"""Audit Python runtime versions, verify PyPI packages, query OSV CVEs, and run safe upgrades."""

import concurrent.futures
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from importlib import metadata as importlib_metadata
from typing import Dict, Any, List, Optional, Tuple
from .rules_catalog import normalize_lang

PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,80}$")
REQ_LINE_RE = re.compile(r"^\s*([a-zA-Z0-9][a-zA-Z0-9._-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)?\s*([a-zA-Z0-9.*+-]+)?")

# Keep an offline fallback release table so checks stay responsive without internet access.
FALLBACK_PYTHON_CYCLES = [
    {"cycle": "3.14", "latest": "3.14.0", "eol": "2030-10-31", "lts": False},
    {"cycle": "3.13", "latest": "3.13.3", "eol": "2029-10-31", "lts": False},
    {"cycle": "3.12", "latest": "3.12.10", "eol": "2028-10-31", "lts": False},
    {"cycle": "3.11", "latest": "3.11.12", "eol": "2027-10-31", "lts": False},
]


def _parse_ver_tuple(ver_str: str) -> Tuple[int, ...]:
    nums = []
    for part in str(ver_str).split("."):
        m = re.match(r"^(\d+)", part.strip())
        if m:
            nums.append(int(m.group(1)))
        else:
            break
    return tuple(nums)


def _fetch_json(url: str, data: Optional[bytes] = None, timeout: float = 3.5) -> Any:
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "AIShield-Guard/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_python_runtime(lang: str = "pt") -> Dict[str, Any]:
    """Compare the active Python runtime against official stable releases."""
    is_en = normalize_lang(lang) == "en"
    vi = sys.version_info
    current_full = f"{vi.major}.{vi.minor}.{vi.micro}"
    current_minor = f"{vi.major}.{vi.minor}"
    exe_path = sys.executable
    is_conda = "anaconda" in exe_path.lower() or "conda" in exe_path.lower() or os.path.isdir(
        os.path.join(os.path.dirname(exe_path), "conda-meta")
    )

    cycles = FALLBACK_PYTHON_CYCLES
    source_used = "fallback_local"
    try:
        api_cycles = _fetch_json("https://endoflife.date/api/python.json", timeout=3.5)
        if isinstance(api_cycles, list) and len(api_cycles) > 0:
            cycles = api_cycles
            source_used = "endoflife.date / python.org"
    except Exception:
        pass

    sorted_cycles = sorted(cycles, key=lambda c: _parse_ver_tuple(c.get("cycle", "0")), reverse=True)
    latest_series = sorted_cycles[0] if sorted_cycles else FALLBACK_PYTHON_CYCLES[0]
    latest_cycle_str = str(latest_series.get("cycle", "3.13"))
    latest_patch_str = str(latest_series.get("latest", latest_cycle_str))

    current_series_info = next((c for c in sorted_cycles if str(c.get("cycle")) == current_minor), None)
    is_eol = bool(current_series_info and current_series_info.get("eol") is True)
    eol_date = str(current_series_info.get("eol")) if current_series_info else ("unknown" if is_en else "desconhecido")

    up_to_date = _parse_ver_tuple(current_full) >= _parse_ver_tuple(latest_patch_str)
    minor_outdated = _parse_ver_tuple(current_minor) < _parse_ver_tuple(latest_cycle_str)

    if is_conda:
        recommended_cmd = f"conda install -y python={latest_cycle_str}"
        upgrade_mode = "conda"
    else:
        recommended_cmd = f"winget upgrade Python.Python.{latest_cycle_str}"
        upgrade_mode = "winget"

    if is_eol:
        status_label = (
            "Critical: Python version reached End-of-Life (EOL)"
            if is_en else
            "Critico: Versao fora de suporte oficial (EOL)"
        )
        status_level = "CRITICAL"
    elif minor_outdated:
        status_label = (
            f"Upgrade available ({current_minor} -> {latest_cycle_str})"
            if is_en else
            f"Atualizacao disponivel ({current_minor} -> {latest_cycle_str})"
        )
        status_level = "MEDIUM"
    elif not up_to_date:
        status_label = (
            f"New security patch available ({latest_patch_str})"
            if is_en else
            f"Novo patch de seguranca disponivel ({latest_patch_str})"
        )
        status_level = "LOW"
    else:
        status_label = (
            "Up to date on the latest official series"
            if is_en else
            "Atualizado na serie oficial mais recente"
        )
        status_level = "OK"

    return {
        "current_version": current_full,
        "current_series": current_minor,
        "executable": exe_path,
        "is_anaconda": is_conda,
        "latest_official_series": latest_cycle_str,
        "latest_official_version": latest_patch_str,
        "eol_date": eol_date,
        "up_to_date": up_to_date and not minor_outdated,
        "minor_outdated": minor_outdated,
        "status_label": status_label,
        "status_level": status_level,
        "source": source_used,
        "upgrade_mode": upgrade_mode,
        "recommended_command": recommended_cmd,
    }


def _read_project_requirements(target_dir: str) -> Tuple[List[Dict[str, str]], str]:
    req_path = os.path.join(target_dir, "requirements.txt")
    items: List[Dict[str, str]] = []
    seen = set()

    if os.path.isfile(req_path):
        with open(req_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                clean = line.strip()
                if not clean or clean.startswith(("#", "-r", "--")):
                    continue
                m = REQ_LINE_RE.match(clean)
                if m:
                    pkg = m.group(1)
                    if pkg.lower() in seen:
                        continue
                    seen.add(pkg.lower())
                    items.append({
                        "name": pkg,
                        "declared_op": m.group(2) or "",
                        "declared_version": m.group(3) or "",
                    })
        return items, "requirements.txt"

    # Caso nao haja requirements.txt, inspeciona pacotes chave de Data Science / Web instalados
    key_ds_pkgs = ["pandas", "numpy", "scikit-learn", "flask", "requests", "urllib3", "cryptography", "pyyaml", "duckdb", "sqlalchemy"]
    for dist in importlib_metadata.distributions():
        name = dist.metadata.get("Name") or ""
        if name.lower() in key_ds_pkgs and name.lower() not in seen:
            seen.add(name.lower())
            items.append({
                "name": name,
                "declared_op": "installed",
                "declared_version": dist.version,
            })
    return sorted(items, key=lambda x: x["name"].lower()), "ambiente_local"


def _installed_version(pkg_name: str) -> Optional[str]:
    try:
        return importlib_metadata.version(pkg_name)
    except importlib_metadata.PackageNotFoundError:
        return None


def _check_single_pypi(pkg_info: Dict[str, str]) -> Dict[str, Any]:
    name = pkg_info["name"]
    installed = _installed_version(name)
    declared_ver = pkg_info["declared_version"]
    check_ver = declared_ver if pkg_info["declared_op"] == "==" else (installed or declared_ver)

    result = {
        "name": name,
        "declared_spec": f"{pkg_info['declared_op']}{declared_ver}" if declared_ver else "sem versao fixa",
        "installed_version": installed or "nao instalado",
        "checked_version": check_ver,
        "latest_pypi": None,
        "exists_on_pypi": True,
        "outdated": False,
        "vulnerabilities": [],
        "status": "OK",
    }

    try:
        pypi_data = _fetch_json(f"https://pypi.org/pypi/{name}/json", timeout=3.5)
        latest = pypi_data.get("info", {}).get("version")
        result["latest_pypi"] = latest
        if check_ver and latest:
            result["outdated"] = _parse_ver_tuple(check_ver) < _parse_ver_tuple(latest)
            if result["outdated"]:
                result["status"] = "OUTDATED"
    except urllib.error.HTTPError as he:
        if he.code == 404:
            result["exists_on_pypi"] = False
            result["status"] = "HALLUCINATED"
    except Exception:
        result["status"] = "UNCHECKED"

    return result


def _attach_osv_vulnerabilities(packages: List[Dict[str, Any]]) -> None:
    """Query the batch OSV.dev API to attach known CVEs to each verified package."""
    queries = []
    index_map = []
    for idx, pkg in enumerate(packages):
        if pkg["exists_on_pypi"] and pkg["checked_version"]:
            queries.append({
                "version": pkg["checked_version"],
                "package": {"name": pkg["name"], "ecosystem": "PyPI"},
            })
            index_map.append(idx)

    if not queries:
        return

    try:
        payload = json.dumps({"queries": queries}).encode("utf-8")
        resp = _fetch_json("https://api.osv.dev/v1/querybatch", data=payload, timeout=4.5)
        results = resp.get("results") or []
        for q_idx, item in enumerate(results):
            vulns = item.get("vulns") or []
            if not vulns:
                continue
            pkg_idx = index_map[q_idx]
            formatted = []
            for v in vulns[:5]:
                formatted.append({
                    "id": v.get("id", "CVE/GHSA"),
                    "summary": v.get("summary") or "Vulnerabilidade conhecida registrada na base OSV.",
                })
            packages[pkg_idx]["vulnerabilities"] = formatted
            packages[pkg_idx]["status"] = "VULNERABLE"
    except Exception:
        pass


def inspect_python_and_packages(target_dir: str, lang: str = "pt") -> Dict[str, Any]:
    """Audit the Python runtime, check PyPI existence, and map known OSV vulnerabilities."""
    code = normalize_lang(lang)
    runtime = check_python_runtime(lang=code)
    req_items, source_kind = _read_project_requirements(target_dir)

    packages: List[Dict[str, Any]] = []
    if req_items:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            packages = list(pool.map(_check_single_pypi, req_items[:30]))
        _attach_osv_vulnerabilities(packages)

    vulnerable_count = sum(1 for p in packages if p["status"] == "VULNERABLE")
    hallucinated_count = sum(1 for p in packages if p["status"] == "HALLUCINATED")
    outdated_count = sum(1 for p in packages if p["status"] == "OUTDATED")

    return {
        "status": "success",
        "lang": code,
        "runtime": runtime,
        "package_source": source_kind,
        "packages": packages,
        "summary": {
            "total": len(packages),
            "vulnerable": vulnerable_count,
            "hallucinated": hallucinated_count,
            "outdated": outdated_count,
        },
    }


def run_safe_update(action: str, package_name: str = "", target_python_series: str = "") -> Dict[str, Any]:
    """Run a strict allowlisted pip or conda upgrade command without shell interpolation."""
    py_exe = sys.executable

    if action == "upgrade_package":
        pkg = (package_name or "").strip()
        if not PKG_NAME_RE.match(pkg):
            raise ValueError(f"Nome de pacote invalido: '{pkg}'.")
        cmd = [py_exe, "-m", "pip", "install", "--upgrade", pkg]
    elif action == "upgrade_python":
        series = (target_python_series or "3.13").strip()
        if not re.match(r"^3\.\d{1,2}$", series):
            raise ValueError("Serie Python invalida para atualizacao.")
        conda_exe = os.path.join(os.path.dirname(py_exe), "Scripts", "conda.exe")
        if os.path.isfile(conda_exe):
            cmd = [conda_exe, "install", "-y", f"python={series}"]
        else:
            cmd = ["winget", "upgrade", f"Python.Python.{series}"]
    else:
        raise ValueError(f"Acao de atualizacao desconhecida: '{action}'.")

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    output_tail = "\n".join((proc.stdout + "\n" + proc.stderr).splitlines()[-25:])
    if proc.returncode != 0:
        return {
            "status": "error",
            "command": " ".join(cmd),
            "output": output_tail,
            "message": "Falha ao executar o comando de atualizacao no ambiente.",
        }

    return {
        "status": "success",
        "command": " ".join(cmd),
        "output": output_tail,
        "message": f"Comando concluido com sucesso: {' '.join(cmd)}",
    }
