"""Fast security scanner using stdlib os.scandir, Python AST, and compiled regex rules."""

import ast
import datetime
import json
import os
import time
from typing import Dict, Any, List, Set, Optional
from .rules_catalog import (
    AST_RULE_DOCS,
    CATEGORY_LABELS,
    CATEGORY_LABELS_EN,
    ENV_KEY_PATTERN,
    GENERIC_SECRET_ASSIGN_RE,
    SENSITIVE_ASSIGN_NAMES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    build_finding,
    get_active_regex_rules,
    get_all_tests_documentation,
    is_placeholder_secret,
    mask_secret_value,
    normalize_lang,
    pick_lang_text,
)
from .git_auditor import audit_git_protection
from .memory_manager import collect_memory
from .preferences_manager import load_preferences

IGNORED_DIRS: Set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".env_venv",
    ".ipynb_checkpoints", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "anaconda3", "miniconda3", "site-packages", "egg-info",
}

TEXT_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".html", ".htm",
    ".css", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".sql", ".sh", ".ps1", ".bat", ".md", ".txt", ".dockerfile", ".tf",
}

SPECIAL_TEXT_FILENAMES: Set[str] = {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}

DATA_SENSITIVE_EXTS: Set[str] = {
    ".sqlite", ".sqlite3", ".db", ".duckdb", ".pem", ".key", ".p12", ".pfx",
}

PUBLIC_DIR_MARKERS: Set[str] = {"static", "public", "htdocs", "www", "assets", "dist", "build"}
MAX_FILE_SIZE_BYTES = 1_500_000  # Skip files above 1.5 MB to keep scan latency under one second.


class _PythonASTSecurityVisitor(ast.NodeVisitor):
    """Inspect Python AST nodes to detect SQL injection, unsafe deserialization, and debug flags."""

    def __init__(self, rel_path: str, source_lines: List[str], lang: str = "pt"):
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.lang = normalize_lang(lang)
        self.findings: List[Dict[str, Any]] = []
        self._seen: Set[tuple] = set()

    def _line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add_ast_finding(self, rule_id: str, lineno: int, custom_snippet: str = "") -> None:
        key = (rule_id, lineno)
        if key in self._seen:
            return
        self._seen.add(key)
        meta = AST_RULE_DOCS[rule_id]
        snippet = custom_snippet or self._line_snippet(lineno)
        self.findings.append(
            build_finding(
                rule_id=rule_id,
                file_path=self.rel_path,
                line=lineno,
                snippet=snippet,
                category=meta["category"],
                severity=meta["severity"],
                title=pick_lang_text(meta, "title", self.lang),
                plain_why=pick_lang_text(meta, "plain_why", self.lang),
                how_to_fix=pick_lang_text(meta, "how_to_fix", self.lang),
                fix_example=meta["fix_example"],
                lang=self.lang,
            )
        )

    @staticmethod
    def _dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _PythonASTSecurityVisitor._dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _is_dynamic_sql_arg(arg_node: ast.AST) -> bool:
        if isinstance(arg_node, ast.JoinedStr):
            return True
        if isinstance(arg_node, ast.BinOp) and isinstance(arg_node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, ast.Attribute) and arg_node.func.attr == "format":
            return True
        return False

    def visit_Assign(self, node: ast.Assign) -> Any:
        for tgt in node.targets:
            var_name = self._dotted_name(tgt).split(".")[-1].lower()
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                raw_val = node.value.value
                if var_name in SENSITIVE_ASSIGN_NAMES and not is_placeholder_secret(raw_val):
                    masked = mask_secret_value(raw_val)
                    self._add_ast_finding(
                        "AST-HARDCODED-SECRET",
                        node.lineno,
                        f"{self._dotted_name(tgt)} = '{masked}'",
                    )
                elif var_name == "debug" and node.value.value is True:
                    self._add_ast_finding("AST-DEBUG-TRUE", node.lineno)
            elif var_name == "debug" and isinstance(node.value, ast.Constant) and node.value.value is True:
                self._add_ast_finding("AST-DEBUG-TRUE", node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = self._dotted_name(node.func)
        short_name = call_name.split(".")[-1] if call_name else ""

        # 1. SQL Injection em execute() ou read_sql()
        if short_name in ("execute", "executemany", "read_sql", "read_sql_query", "text"):
            target_arg = node.args[0] if node.args else None
            if target_arg and self._is_dynamic_sql_arg(target_arg):
                self._add_ast_finding("AST-SQL-INJECTION", node.lineno)

        # 2. Desserializacao insegura
        if call_name in ("pickle.load", "pickle.loads", "cPickle.loads", "joblib.load"):
            self._add_ast_finding("AST-UNSAFE-PICKLE", node.lineno)
        elif call_name == "torch.load":
            has_safe_weights = any(
                kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if not has_safe_weights:
                self._add_ast_finding("AST-UNSAFE-PICKLE", node.lineno)
        elif call_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and "SafeLoader" in self._dotted_name(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                self._add_ast_finding("AST-UNSAFE-YAML", node.lineno)

        # 3. Execucao dinamica / shell injection
        if call_name in ("eval", "exec", "os.system", "os.popen"):
            self._add_ast_finding("AST-CODE-EXEC", node.lineno)
        elif call_name.startswith("subprocess.") and short_name in ("run", "Popen", "call", "check_output", "check_call"):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                self._add_ast_finding("AST-CODE-EXEC", node.lineno)

        # 4. debug=True ou verify=False
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self._add_ast_finding("AST-DEBUG-TRUE", node.lineno)
            elif kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add_ast_finding("AST-SSL-VERIFY-FALSE", node.lineno)

        self.generic_visit(node)


class ProjectSecurityScanner:
    """Executor principal da auditoria estatica, segredos, Git e Data Science."""

    def __init__(self, self_project_root: Optional[str] = None):
        self.self_project_root = os.path.abspath(self_project_root) if self_project_root else None

    def scan_directory(self, target_dir: str, lang: str = "pt", prefs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        started = time.perf_counter()
        code = normalize_lang(lang)
        is_en = code == "en"
        abs_target = os.path.abspath(target_dir.strip())
        if not os.path.isdir(abs_target):
            raise FileNotFoundError(
                f"Folder does not exist: '{abs_target}'" if is_en else f"A pasta informada nao existe: '{abs_target}'"
            )

        active_prefs = prefs if prefs is not None else load_preferences()
        disabled_rules = set(active_prefs.get("disabled_rules") or [])
        compiled_regex_rules = get_active_regex_rules(active_prefs)
        docs_meta = get_all_tests_documentation(lang=code, prefs=active_prefs)

        git_audit = audit_git_protection(abs_target, lang=code)
        findings: List[Dict[str, Any]] = [
            f for f in git_audit["findings"] if f["rule_id"] not in disabled_rules
        ]

        files_scanned = 0
        total_lines = 0
        file_inventory = []

        for file_path in self._iter_files(abs_target):
            rel_path = os.path.relpath(file_path, abs_target).replace("\\", "/")
            base_name = os.path.basename(file_path)
            ext = os.path.splitext(base_name)[1].lower()
            parts_lower = {p.lower() for p in rel_path.split("/")[:-1]}

            if ext in DATA_SENSITIVE_EXTS:
                in_public = bool(parts_lower.intersection(PUBLIC_DIR_MARKERS))
                if in_public and "EXP-DB-IN-PUBLIC-DIR" not in disabled_rules:
                    findings.append(
                        build_finding(
                            rule_id="EXP-DB-IN-PUBLIC-DIR",
                            file_path=rel_path,
                            line=1,
                            snippet=(f"Sensitive file in public web directory: {rel_path}" if is_en else f"Arquivo sensivel dentro de pasta publica: {rel_path}"),
                            category="EXPOSED_DATA",
                            severity="CRITICAL",
                            title=(f"Database or key inside public folder ({rel_path})" if is_en else f"Banco de dados ou chave em pasta publica ({rel_path})"),
                            plain_why=(
                                "Files inside static/, public/, or htdocs/ folders can be downloaded directly by any internet visitor."
                                if is_en else
                                "Arquivos dentro de pastas como static/, public/ ou htdocs/ podem ser baixados diretamente por qualquer visitante pela URL do site."
                            ),
                            how_to_fix=(
                                "Move databases and private keys outside public directories and ignore those extensions in .gitignore."
                                if is_en else
                                "Mova o banco de dados ou chave privada para fora da pasta web publica e bloqueie a extensao no .gitignore."
                            ),
                            fix_example="# Move databases outside static/ or public/\nDB_PATH = BASE_DIR / 'private_data' / 'app.sqlite'",
                            lang=code,
                        )
                    )
                elif not in_public and not self._is_extension_ignored(ext, git_audit["checklist"]) and "EXP-UNPROTECTED-DB-FILE" not in disabled_rules:
                    findings.append(
                        build_finding(
                            rule_id="EXP-UNPROTECTED-DB-FILE",
                            file_path=rel_path,
                            line=1,
                            snippet=(f"Local file {rel_path} omitted from .gitignore" if is_en else f"Arquivo local {rel_path} nao coberto pelo .gitignore"),
                            category="EXPOSED_DATA",
                            severity="HIGH",
                            title=(f"Unprotected local database or key: {base_name}" if is_en else f"Banco/chave local desprotegido do Git: {base_name}"),
                            plain_why=(
                                "This file lives in the workspace and is not blocked by .gitignore, so Git may publish private data."
                                if is_en else
                                "Esse arquivo esta na pasta do projeto e o seu .gitignore atual nao bloqueia essa extensao. Ao subir o codigo, seus dados podem ir junto."
                            ),
                            how_to_fix=(
                                "Add this file pattern to .gitignore using the automatic fix button."
                                if is_en else
                                "Adicione o padrao da extensao no .gitignore usando o botao de correcao automatica."
                            ),
                            fix_example=f"*{ext}",
                            lang=code,
                        )
                    )
                continue

            if base_name == ".env" or base_name.startswith(".env."):
                if base_name.endswith((".example", ".sample", ".template")):
                    continue
                files_scanned += 1
                total_lines += self._inspect_env_file(
                    file_path, rel_path, git_audit, findings,
                    lang=code, regex_rules=compiled_regex_rules, disabled_rules=disabled_rules
                )
                continue

            if ext != ".ipynb" and ext not in TEXT_EXTENSIONS and base_name.lower() not in SPECIAL_TEXT_FILENAMES:
                continue

            try:
                size = os.path.getsize(file_path)
                if size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            files_scanned += 1
            file_inventory.append(rel_path)

            if ext == ".ipynb":
                total_lines += self._scan_notebook(
                    file_path, rel_path, findings,
                    lang=code, regex_rules=compiled_regex_rules, disabled_rules=disabled_rules
                )
            elif ext == ".py":
                total_lines += self._scan_python_file(
                    file_path, rel_path, findings,
                    lang=code, regex_rules=compiled_regex_rules, disabled_rules=disabled_rules
                )
            else:
                total_lines += self._scan_text_file(
                    file_path, rel_path, findings,
                    lang=code, regex_rules=compiled_regex_rules, disabled_rules=disabled_rules
                )

        findings = [f for f in self._deduplicate_findings(findings) if f["rule_id"] not in disabled_rules]
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["file_path"], f["line"]))

        score, grade, verdict = self._compute_score(findings, lang=code)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        elapsed_s = round(elapsed_ms / 1000.0, 2)

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_map = CATEGORY_LABELS_EN if is_en else CATEGORY_LABELS
        cat_counts = {k: 0 for k in cat_map}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
            cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

        # Reclaim intermediate AST/text buffers from RAM right after completing the scan.
        collect_memory(trim_working_set=True)

        now_dt = datetime.datetime.now()
        return {
            "status": "success",
            "lang": code,
            "is_live_scan": True,
            "scan_timestamp": now_dt.strftime("%H:%M:%S"),
            "scan_iso": now_dt.isoformat(timespec="seconds"),
            "target_dir": abs_target,
            "project_name": os.path.basename(abs_target) or abs_target,
            "scan_time_ms": elapsed_ms,
            "scan_time_s": elapsed_s,
            "files_scanned": files_scanned,
            "total_lines": total_lines,
            "score": score,
            "grade": grade,
            "verdict": verdict,
            "total_findings": len(findings),
            "active_rules_count": docs_meta["enabled_tests"],
            "disabled_rules_count": docs_meta["disabled_tests"],
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
            "category_labels": cat_map,
            "git_audit": git_audit,
            "findings": findings,
        }

    def _iter_files(self, root_dir: str):
        root_name = os.path.basename(os.path.normpath(root_dir)).lower()
        stack = [root_dir]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in IGNORED_DIRS:
                                continue
                            # Skip intentional vulnerable demo fixtures when scanning a parent repo.
                            if entry.name.lower() == "demo_vulnerable_project" and root_name != "demo_vulnerable_project":
                                continue
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry.path
            except PermissionError:
                continue

    @staticmethod
    def _is_extension_ignored(ext: str, checklist: List[Dict[str, Any]]) -> bool:
        target_pat = f"*{ext}"
        for item in checklist:
            if item["pattern"].lower() == target_pat and item["covered"]:
                return True
        return False

    def _inspect_env_file(
        self,
        file_path: str,
        rel_path: str,
        git_audit: Dict[str, Any],
        findings: List[Dict[str, Any]],
        lang: str = "pt",
        regex_rules: Optional[List[Dict[str, Any]]] = None,
        disabled_rules: Optional[Set[str]] = None,
    ) -> int:
        is_en = normalize_lang(lang) == "en"
        disabled_rules = disabled_rules or set()
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()

        env_protected = any(
            item["pattern"] == ".env" and item["covered"] for item in git_audit["checklist"]
        )
        populated_keys: List[str] = []
        for idx, line in enumerate(lines, start=1):
            m = ENV_KEY_PATTERN.match(line)
            if m and not line.strip().startswith("#"):
                key_name, val = m.group(1), m.group(2)
                if not is_placeholder_secret(val):
                    populated_keys.append(key_name)
                    self._scan_lines(
                        [line], rel_path, findings, start_line=idx, lang=lang,
                        regex_rules=regex_rules, disabled_rules=disabled_rules
                    )

        if not env_protected and "EXP-ENV-UNPROTECTED" not in disabled_rules:
            keys_preview = ", ".join(populated_keys[:5]) if populated_keys else ("variables" if is_en else "variaveis")
            findings.append(
                build_finding(
                    rule_id="EXP-ENV-UNPROTECTED",
                    file_path=rel_path,
                    line=1,
                    snippet=(
                        f"File {rel_path} holds {len(populated_keys)} key(s) ({keys_preview}) without .gitignore protection"
                        if is_en else
                        f"Arquivo {rel_path} com {len(populated_keys)} chave(s) ({keys_preview}) sem protecao no .gitignore"
                    ),
                    category="EXPOSED_DATA",
                    severity="CRITICAL",
                    title=(
                        f"Unprotected {rel_path} file can leak credentials to Git"
                        if is_en else
                        f"Arquivo {rel_path} desprotegido pode subir senhas para o Git"
                    ),
                    plain_why=(
                        "Your .env file contains real credentials and is missing from .gitignore. Running 'git add .' will publish every secret."
                        if is_en else
                        "Seu arquivo .env contem senhas reais e NAO esta bloqueado no .gitignore. No primeiro 'git add .', suas chaves vao publicamente para o GitHub."
                    ),
                    how_to_fix=(
                        "Add .env to .gitignore immediately in the Git Protection tab and keep only a blank .env.example."
                        if is_en else
                        "Adicione .env ao .gitignore imediatamente usando a aba Git & .gitignore e mantenha apenas um .env.example vazio como modelo."
                    ),
                    fix_example=".env\n.env.*",
                    lang=lang,
                )
            )
        return len(lines)

    def _scan_python_file(
        self,
        file_path: str,
        rel_path: str,
        findings: List[Dict[str, Any]],
        lang: str = "pt",
        regex_rules: Optional[List[Dict[str, Any]]] = None,
        disabled_rules: Optional[Set[str]] = None,
    ) -> int:
        disabled_rules = disabled_rules or set()
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        lines = source.splitlines()

        # Run regex sweep first to catch hardcoded credentials and local URLs.
        self._scan_lines(lines, rel_path, findings, lang=lang, regex_rules=regex_rules, disabled_rules=disabled_rules)

        # Parse the AST to uncover structural SAST risks such as dynamic SQL or unsafe pickle calls.
        try:
            tree = ast.parse(source, filename=rel_path)
            visitor = _PythonASTSecurityVisitor(rel_path, lines, lang=lang)
            visitor.visit(tree)
            findings.extend([f for f in visitor.findings if f["rule_id"] not in disabled_rules])
            del tree, visitor
        except SyntaxError:
            # Keep regex findings even when the file has incomplete Python syntax.
            pass

        line_count = len(lines)
        del source, lines
        return line_count

    def _scan_text_file(
        self,
        file_path: str,
        rel_path: str,
        findings: List[Dict[str, Any]],
        lang: str = "pt",
        regex_rules: Optional[List[Dict[str, Any]]] = None,
        disabled_rules: Optional[Set[str]] = None,
    ) -> int:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        self._scan_lines(lines, rel_path, findings, lang=lang, regex_rules=regex_rules, disabled_rules=disabled_rules)
        return len(lines)

    def _scan_notebook(
        self,
        file_path: str,
        rel_path: str,
        findings: List[Dict[str, Any]],
        lang: str = "pt",
        regex_rules: Optional[List[Dict[str, Any]]] = None,
        disabled_rules: Optional[Set[str]] = None,
    ) -> int:
        code = normalize_lang(lang)
        is_en = code == "en"
        disabled_rules = disabled_rules or set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                nb = json.load(f)
        except Exception:
            return 0

        cells = nb.get("cells") or []
        total_lines = 0
        cells_with_outputs = 0

        for idx, cell in enumerate(cells, start=1):
            if cell.get("cell_type") != "code":
                continue
            raw_src = cell.get("source") or []
            src_lines = raw_src if isinstance(raw_src, list) else str(raw_src).splitlines()
            clean_lines = [ln.rstrip("\n") for ln in src_lines]
            total_lines += len(clean_lines)

            cell_tag = f"{rel_path} [Cell {idx}]" if is_en else f"{rel_path} [Celula {idx}]"
            self._scan_lines(clean_lines, cell_tag, findings, lang=code, regex_rules=regex_rules, disabled_rules=disabled_rules)

            # Strip notebook cell magics (%pip, !ls) so standard ast.parse succeeds.
            py_only = "\n".join(
                ln if not ln.lstrip().startswith(("%", "!")) else "" for ln in clean_lines
            )
            try:
                tree = ast.parse(py_only)
                visitor = _PythonASTSecurityVisitor(cell_tag, clean_lines, lang=code)
                visitor.visit(tree)
                findings.extend([f for f in visitor.findings if f["rule_id"] not in disabled_rules])
            except SyntaxError:
                pass

            outputs = cell.get("outputs") or []
            if outputs:
                cells_with_outputs += 1
                out_text = json.dumps(outputs, ensure_ascii=False)
                out_tag = f"{rel_path} [Output Cell {idx}]" if is_en else f"{rel_path} [Output Celula {idx}]"
                self._scan_lines([out_text], out_tag, findings, lang=code, regex_rules=regex_rules, disabled_rules=disabled_rules)

        if cells_with_outputs > 0 and "NB-SAVED-OUTPUTS" not in disabled_rules:
            meta = AST_RULE_DOCS["NB-SAVED-OUTPUTS"]
            findings.append(
                build_finding(
                    rule_id="NB-SAVED-OUTPUTS",
                    file_path=rel_path,
                    line=1,
                    snippet=(
                        f"{cells_with_outputs} cell(s) with saved outputs in .ipynb"
                        if is_en else
                        f"{cells_with_outputs} celula(s) com outputs salvos no .ipynb"
                    ),
                    category=meta["category"],
                    severity=meta["severity"],
                    title=pick_lang_text(meta, "title", code),
                    plain_why=pick_lang_text(meta, "plain_why", code),
                    how_to_fix=pick_lang_text(meta, "how_to_fix", code),
                    fix_example=meta["fix_example"],
                    lang=code,
                )
            )
        return total_lines

    def _scan_lines(
        self,
        lines: List[str],
        rel_path: str,
        findings: List[Dict[str, Any]],
        start_line: int = 1,
        lang: str = "pt",
        regex_rules: Optional[List[Dict[str, Any]]] = None,
        disabled_rules: Optional[Set[str]] = None,
    ) -> None:
        code = normalize_lang(lang)
        is_en = code == "en"
        disabled_rules = disabled_rules or set()
        rules_to_run = regex_rules if regex_rules is not None else get_active_regex_rules()
        is_gitignore = os.path.basename(rel_path) == ".gitignore"
        if is_gitignore:
            return
        norm_rel = rel_path.replace("\\", "/").lower()
        is_doc_file = norm_rel.endswith((".md", ".txt"))
        is_rule_catalog_file = norm_rel.startswith("core/") and os.path.basename(norm_rel) in (
            "rules_catalog.py",
            "guardrail_generator.py",
        )

        for offset, line in enumerate(lines):
            lineno = start_line + offset
            stripped = line.strip()
            if not stripped or "guardrail-ignore" in line:
                continue

            for rule in rules_to_run:
                rule_id = rule["id"]
                # Skip illustrative doc/rule-definition false positives while keeping real secret checks active.
                if (is_doc_file or is_rule_catalog_file) and rule_id in (
                    "DEP-LOCALHOST-REF",
                    "DEP-LOCAL-PATH",
                    "EXP-CORS-WILDCARD",
                    "EXP-DB-URI-CRED",
                ):
                    continue
                if rule_id == "DEP-LOCALHOST-REF" and ("os.getenv(" in line or "os.environ.get(" in line):
                    continue
                match = rule["pattern"].search(line)
                if not match:
                    continue
                snippet = line
                if rule.get("mask_match"):
                    matched_txt = match.group(0)
                    snippet = line.replace(matched_txt, mask_secret_value(matched_txt))
                findings.append(
                    build_finding(
                        rule_id=rule["id"],
                        file_path=rel_path,
                        line=lineno,
                        snippet=snippet,
                        category=rule["category"],
                        severity=rule["severity"],
                        title=pick_lang_text(rule, "title", code),
                        plain_why=pick_lang_text(rule, "plain_why", code),
                        how_to_fix=pick_lang_text(rule, "how_to_fix", code),
                        fix_example=rule.get("fix_example", ""),
                        lang=code,
                    )
                )

            if "SEC-GENERIC-LITERAL" not in disabled_rules:
                gen = GENERIC_SECRET_ASSIGN_RE.search(line)
                if gen:
                    var_lbl, raw_secret = gen.group(1), gen.group(2)
                    if not is_placeholder_secret(raw_secret):
                        masked = mask_secret_value(raw_secret)
                        safe_line = line.replace(raw_secret, masked)
                        findings.append(
                            build_finding(
                                rule_id="SEC-GENERIC-LITERAL",
                                file_path=rel_path,
                                line=lineno,
                                snippet=safe_line,
                                category="SECRETS",
                                severity="HIGH",
                                title=(
                                    f"Hardcoded credential assigned to '{var_lbl}'"
                                    if is_en else
                                    f"Credencial fixa atribuida a '{var_lbl}'"
                                ),
                                plain_why=(
                                    "Passwords and secrets written straight into code remain readable to anyone with repository or Git history access."
                                    if is_en else
                                    "Senhas e segredos gravados direto no codigo ficam visiveis para qualquer pessoa com acesso ao repositorio ou historico Git."
                                ),
                                how_to_fix=(
                                    "Move the literal into an environment variable and read it dynamically."
                                    if is_en else
                                    "Mova o valor para uma variavel de ambiente segura e carregue dinamicamente."
                                ),
                                fix_example=f"{var_lbl.upper()} = os.getenv('{var_lbl.upper()}')",
                                lang=code,
                            )
                        )

    @staticmethod
    def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate identical findings on the same file and line across regex and AST passes."""
        seen: Set[tuple] = set()
        unique: List[Dict[str, Any]] = []
        for f in findings:
            key = (f["file_path"], f["line"], f["rule_id"])
            if key in seen:
                continue
            # Suppress generic secret alerts when a specific provider key already matched the same line.
            if f["rule_id"] in ("SEC-GENERIC-LITERAL", "AST-HARDCODED-SECRET"):
                alt_keys = {
                    (f["file_path"], f["line"], "SEC-GENERIC-LITERAL"),
                    (f["file_path"], f["line"], "SEC-OPENAI-KEY"),
                    (f["file_path"], f["line"], "SEC-GOOGLE-KEY"),
                    (f["file_path"], f["line"], "SEC-AWS-KEY"),
                    (f["file_path"], f["line"], "SEC-GITHUB-TOKEN"),
                    (f["file_path"], f["line"], "SEC-STRIPE-KEY"),
                }
                if any(k in seen for k in alt_keys):
                    continue
            seen.add(key)
            unique.append(f)
        return unique

    @staticmethod
    def _compute_score(findings: List[Dict[str, Any]], lang: str = "pt") -> tuple:
        is_en = normalize_lang(lang) == "en"
        penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 2) for f in findings)
        score = max(0, min(100, 100 - penalty))
        if score >= 90 and not any(f["severity"] == "CRITICAL" for f in findings):
            grade = "A"
            verdict = "Ready to publish" if is_en else "Pronto para publicar"
        elif score >= 75 and not any(f["severity"] == "CRITICAL" for f in findings):
            grade = "B"
            verdict = "Good, minor adjustments advised" if is_en else "Bom, com ajustes menores recomendados"
        elif score >= 55:
            grade = "C"
            verdict = "Attention needed before deploy" if is_en else "Atenção necessária antes do deploy"
        elif score >= 35:
            grade = "D"
            verdict = "Elevated risk - fix before push" if is_en else "Risco elevado - corrija antes de subir"
        else:
            grade = "F"
            verdict = "Blocked: critical exposure risk" if is_en else "Bloqueado: risco crítico de vazamento"
        return score, grade, verdict
