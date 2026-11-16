"""Core security auditor package for guardrail code."""

from .rules_catalog import CATEGORY_LABELS, SEVERITY_WEIGHTS, get_all_tests_documentation, mask_secret_value
from .scanner_engine import ProjectSecurityScanner
from .git_auditor import audit_git_protection, fix_gitignore
from .env_updater import inspect_python_and_packages, run_safe_update
from .report_exporter import export_html_report, export_markdown_report, export_json_report
from .guardrail_generator import build_custom_skill, list_guardrail_templates, install_guardrail_to_project
from .memory_manager import collect_memory
from .preferences_manager import (
    load_preferences,
    toggle_rule_status,
    toggle_module_installation,
    add_custom_rule,
    remove_custom_rule,
    update_github_repo_url,
    check_github_module_updates,
    download_github_module_updates,
)

__all__ = [
    "CATEGORY_LABELS",
    "SEVERITY_WEIGHTS",
    "get_all_tests_documentation",
    "mask_secret_value",
    "ProjectSecurityScanner",
    "audit_git_protection",
    "fix_gitignore",
    "inspect_python_and_packages",
    "run_safe_update",
    "export_html_report",
    "export_markdown_report",
    "export_json_report",
    "build_custom_skill",
    "list_guardrail_templates",
    "install_guardrail_to_project",
    "collect_memory",
    "load_preferences",
    "toggle_rule_status",
    "toggle_module_installation",
    "add_custom_rule",
    "remove_custom_rule",
    "update_github_repo_url",
    "check_github_module_updates",
    "download_github_module_updates",
]
