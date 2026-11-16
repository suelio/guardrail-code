"""Serve the Flask web application and REST API for guardrail code."""

import os
import secrets
import sys
from flask import Flask, Response, jsonify, render_template, request
from core import (
    ProjectSecurityScanner,
    add_custom_rule,
    build_custom_skill,
    check_github_module_updates,
    collect_memory,
    download_github_module_updates,
    export_html_report,
    export_json_report,
    export_markdown_report,
    fix_gitignore,
    get_all_tests_documentation,
    inspect_python_and_packages,
    install_guardrail_to_project,
    list_guardrail_templates,
    load_preferences,
    remove_custom_rule,
    run_safe_update,
    toggle_module_installation,
    toggle_rule_status,
    update_github_repo_url,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_WORK = os.path.dirname(BASE_DIR)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("GUARDRAIL_CODE_SESSION") or secrets.token_hex(32)

scanner = ProjectSecurityScanner(self_project_root=BASE_DIR)


@app.after_request
def add_security_headers(response: Response) -> Response:
    """Attach baseline HTTP security headers and trim memory after heavy API calls."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.path in ("/api/scan", "/api/export-report"):
        collect_memory(trim_working_set=False)
    return response


def _directory_markers(dir_path: str):
    """Detect common repository files so the folder browser highlights real projects."""
    markers = []
    try:
        names = set(os.listdir(dir_path))
        if ".git" in names:
            markers.append("Git")
        if "requirements.txt" in names or "pyproject.toml" in names:
            markers.append("Python")
        if "package.json" in names:
            markers.append("Node")
        if not markers and any(n.endswith(".py") for n in names):
            markers.append("Scripts .py")
    except Exception:
        pass
    return markers


def _directory_bookmarks():
    """Build standard local shortcuts for quick navigation inside the browser modal."""
    home = os.path.expanduser("~")
    candidates = [
        ("00-Geral", PARENT_WORK),
        ("03-git", os.path.join(PARENT_WORK, "03-git")),
        ("Documents", os.path.join(home, "Documents")),
        ("Desktop", os.path.join(home, "Desktop")),
        ("Home", home),
        ("Disco C:", "C:\\"),
    ]
    seen = set()
    items = []
    for label, p in candidates:
        norm = os.path.normpath(p)
        if os.path.isdir(norm) and norm.lower() not in seen:
            seen.add(norm.lower())
            items.append({"label": label, "path": norm})
    return items


@app.route("/")
def index():
    """Render the main dashboard cleanly with no pre-loaded demo folder or automatic scan."""
    return render_template(
        "index.html",
        python_executable=sys.executable,
    )


@app.route("/api/browse-dirs", methods=["POST"])
def api_browse_dirs():
    """List readable subdirectories in pure Python without spawning native OS dialogs."""
    data = request.get_json(silent=True) or {}
    raw_path = (data.get("path") or "").strip()
    target = os.path.normpath(raw_path) if raw_path else PARENT_WORK

    # Fall back to parent workspace when a typed path no longer exists.
    if not os.path.isdir(target):
        target = PARENT_WORK if os.path.isdir(PARENT_WORK) else os.path.expanduser("~")

    parent_dir = os.path.dirname(target)
    if not parent_dir or parent_dir == target:
        parent_dir = ""

    directories = []
    try:
        with os.scandir(target) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.name.startswith("$") or entry.name in ("System Volume Information",):
                    continue
                directories.append({
                    "name": entry.name,
                    "path": os.path.normpath(entry.path),
                    "markers": _directory_markers(entry.path),
                })
        directories.sort(key=lambda d: (0 if d["markers"] else 1, d["name"].lower()))
    except PermissionError:
        return jsonify({"status": "error", "message": f"Permissao negada para listar: {target}"}), 403

    return jsonify({
        "status": "success",
        "current_path": target,
        "parent_path": parent_dir,
        "bookmarks": _directory_bookmarks(),
        "directories": directories,
    })


@app.route("/testes")
def tests_catalog_page():
    """Render the dedicated subpage grouping all executed tests, modules, and Git source."""
    lang = (request.args.get("lang") or "pt").lower()
    prefs = load_preferences()
    docs = get_all_tests_documentation(lang=lang, prefs=prefs)
    return render_template("tests_catalog.html", docs=docs, lang=docs["lang"])


@app.route("/api/tests-catalog", methods=["GET"])
def api_tests_catalog():
    """Return all tests grouped by block, enabled states, and optional modules."""
    lang = (request.args.get("lang") or "pt").lower()
    prefs = load_preferences()
    return jsonify(get_all_tests_documentation(lang=lang, prefs=prefs))


@app.route("/api/tests/toggle-rule", methods=["POST"])
def api_tests_toggle_rule():
    """Enable or disable a single test rule persistently."""
    data = request.get_json(silent=True) or {}
    rule_id = (data.get("rule_id") or "").strip()
    enabled = bool(data.get("enabled"))
    lang = (data.get("lang") or "pt").lower()
    try:
        prefs = toggle_rule_status(rule_id, enabled)
        docs = get_all_tests_documentation(lang=lang, prefs=prefs)
        return jsonify({"status": "success", "docs": docs})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/tests/toggle-module", methods=["POST"])
def api_tests_toggle_module():
    """Install or uninstall an optional security test module."""
    data = request.get_json(silent=True) or {}
    module_id = (data.get("module_id") or "").strip()
    install = bool(data.get("install"))
    lang = (data.get("lang") or "pt").lower()
    try:
        prefs = toggle_module_installation(module_id, install)
        docs = get_all_tests_documentation(lang=lang, prefs=prefs)
        return jsonify({"status": "success", "docs": docs})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/tests/custom-rule", methods=["POST", "DELETE"])
def api_tests_custom_rule():
    """Create or remove a custom regex security rule."""
    data = request.get_json(silent=True) or {}
    lang = (data.get("lang") or "pt").lower()
    try:
        if request.method == "DELETE":
            prefs = remove_custom_rule(data.get("rule_id") or "")
        else:
            prefs = add_custom_rule(data)
        docs = get_all_tests_documentation(lang=lang, prefs=prefs)
        return jsonify({"status": "success", "docs": docs})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/tests/repo-url", methods=["POST"])
def api_tests_repo_url():
    """Update the GitHub repository URL used for sourcing additional test modules."""
    data = request.get_json(silent=True) or {}
    lang = (data.get("lang") or "pt").lower()
    try:
        prefs = update_github_repo_url(data.get("github_repo_url") or "")
        docs = get_all_tests_documentation(lang=lang, prefs=prefs)
        return jsonify({"status": "success", "docs": docs})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/tests/check-updates", methods=["POST"])
def api_tests_check_updates():
    """Check the configured GitHub repository for newly published test modules."""
    data = request.get_json(silent=True) or {}
    lang = (data.get("lang") or "pt").lower()
    try:
        result = check_github_module_updates(lang=lang)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/tests/download-updates", methods=["POST"])
def api_tests_download_updates():
    """Download and register newly published test rules from the GitHub repository."""
    data = request.get_json(silent=True) or {}
    lang = (data.get("lang") or "pt").lower()
    try:
        result = download_github_module_updates(lang=lang)
        prefs = load_preferences()
        docs = get_all_tests_documentation(lang=lang, prefs=prefs)
        result["docs"] = docs
        collect_memory(trim_working_set=True)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/guardrails", methods=["GET"])
def api_guardrails():
    """Return available AI safety guardrails and workspace rule templates."""
    lang = (request.args.get("lang") or "pt").lower()
    return jsonify(list_guardrail_templates(lang=lang))


@app.route("/api/build-custom-skill", methods=["POST"])
def api_build_custom_skill():
    """Build a custom SKILL.md localized in the user's active interface language."""
    data = request.get_json(silent=True) or {}
    slug = (data.get("skill_slug") or "meu-guardrail").strip()
    publish_kw = (data.get("publish_keyword") or "publicar").strip()
    pillars = data.get("pillars")
    lang = (data.get("lang") or "pt").lower()
    return jsonify(build_custom_skill(slug, publish_kw, pillars, lang=lang))


@app.route("/api/install-guardrail", methods=["POST"])
def api_install_guardrail():
    """Save the selected or custom guardrail skill inside the target folder."""
    data = request.get_json(silent=True) or {}
    target_dir = (data.get("target_dir") or "").strip()
    template_key = (data.get("template_key") or "").strip()
    custom_content = data.get("content") or ""
    custom_slug = (data.get("custom_skill_slug") or "").strip()
    lang = (data.get("lang") or "pt").lower()
    try:
        res = install_guardrail_to_project(
            target_dir,
            template_key,
            custom_content,
            custom_skill_slug=custom_slug,
            lang=lang,
        )
        return jsonify(res)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target_dir = (data.get("target_dir") or "").strip()
    lang = (data.get("lang") or "pt").lower()
    if not target_dir:
        msg = "Choose a folder path before running the audit." if lang == "en" else "Escolha uma pasta antes de iniciar a verificação."
        return jsonify({"status": "error", "message": msg}), 400
    try:
        result = scanner.scan_directory(target_dir, lang=lang)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/check-python", methods=["POST"])
def api_check_python():
    data = request.get_json(silent=True) or {}
    target_dir = (data.get("target_dir") or "").strip()
    lang = (data.get("lang") or "pt").lower()
    if not target_dir or not os.path.isdir(target_dir):
        msg = f"Directory not found: {target_dir}" if lang == "en" else f"Pasta não encontrada: {target_dir}"
        return jsonify({"status": "error", "message": msg}), 400
    try:
        result = inspect_python_and_packages(target_dir, lang=lang)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/fix-gitignore", methods=["POST"])
def api_fix_gitignore():
    data = request.get_json(silent=True) or {}
    target_dir = (data.get("target_dir") or "").strip()
    lang = (data.get("lang") or "pt").lower()
    if not target_dir:
        return jsonify({"status": "error", "message": "Target directory required." if lang == "en" else "Informe a pasta alvo para proteger o .gitignore."}), 400
    try:
        res = fix_gitignore(target_dir, lang=lang)
        scan_updated = scanner.scan_directory(target_dir, lang=lang)
        res["scan_result"] = scan_updated
        return jsonify(res)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/update-env", methods=["POST"])
def api_update_env():
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    package_name = (data.get("package_name") or "").strip()
    target_python_series = (data.get("target_python_series") or "").strip()
    try:
        res = run_safe_update(
            action=action,
            package_name=package_name,
            target_python_series=target_python_series,
        )
        code = 200 if res["status"] == "success" else 400
        return jsonify(res), code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/export-report", methods=["POST"])
def api_export_report():
    data = request.get_json(silent=True) or {}
    target_dir = (data.get("target_dir") or "").strip() or DEMO_DIR
    fmt = (data.get("format") or "html").strip().lower()
    lang = (data.get("lang") or "pt").lower()
    env_data = data.get("env_data")
    scan_data = data.get("scan_data")

    try:
        if not scan_data:
            scan_data = scanner.scan_directory(target_dir, lang=lang)
        if fmt == "json":
            content = export_json_report(scan_data, env_data)
            return Response(
                content,
                mimetype="application/json; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="project_exposure_report.json"'},
            )
        if fmt == "markdown":
            content = export_markdown_report(scan_data, env_data, lang=lang)
            return Response(
                content,
                mimetype="text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="project_exposure_report.md"'},
            )
        content = export_html_report(scan_data, env_data, lang=lang)
        return Response(content, mimetype="text/html; charset=utf-8")
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


if __name__ == "__main__":
    host = os.getenv("GUARDRAIL_CODE_HOST", "127.0.0.1")
    port = int(os.getenv("GUARDRAIL_CODE_PORT", "5006"))
    app.run(host=host, port=port, debug=False)
