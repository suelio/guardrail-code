import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.preferences_manager as prefs_mgr
from app import BASE_DIR, app
from core.env_updater import inspect_python_and_packages, run_safe_update
from core.git_auditor import audit_git_protection, fix_gitignore
from core.guardrail_generator import install_guardrail_to_project
from core.memory_manager import collect_memory
from core.report_exporter import export_html_report, export_json_report, export_markdown_report
from core.scanner_engine import ProjectSecurityScanner


class TestGuardrailCode(unittest.TestCase):
    def setUp(self):
        self._tmp_prefs_dir = tempfile.TemporaryDirectory()
        self._tmp_prefs_file = os.path.join(self._tmp_prefs_dir.name, "scanner_preferences.json")
        self._prefs_patcher = patch.object(prefs_mgr, "PREFS_FILE", self._tmp_prefs_file)
        self._prefs_patcher.start()
        self.scanner = ProjectSecurityScanner(self_project_root=BASE_DIR)
        self.client = app.test_client()

    def tearDown(self):
        self._prefs_patcher.stop()
        self._tmp_prefs_dir.cleanup()

    def test_self_project_scan_passes_grade_a_100(self):
        res_self = self.scanner.scan_directory(BASE_DIR, lang="pt")
        self.assertEqual(res_self["status"], "success")
        self.assertEqual(res_self["findings"], [], msg=f"Achados inesperados: {res_self['findings']}")
        self.assertEqual(res_self["score"], 100)
        self.assertEqual(res_self["grade"], "A")
        self.assertIn("scan_time_s", res_self)

    def test_synthetic_scan_and_masking_in_temp_dir(self):
        fake_key = "sk-proj-" + "TestSyntheticValue1234567890AbCdEfGhIjKl"
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as ef:
                ef.write(f"OPENAI_API_KEY={fake_key}\n")
            with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as pf:
                pf.write(
                    "import subprocess, pickle\n"
                    f"KEY = '{fake_key}'\n"
                    "x = eval('1 + 1')\n"
                    "subprocess.run('dir', shell=True)\n"
                )

            res_pt = self.scanner.scan_directory(tmp, lang="pt")
            self.assertEqual(res_pt["status"], "success")
            rule_ids = {f["rule_id"] for f in res_pt["findings"]}
            self.assertIn("SEC-OPENAI-KEY", rule_ids)
            self.assertIn("EXP-ENV-UNPROTECTED", rule_ids)
            self.assertIn("AST-CODE-EXEC", rule_ids)

            serialized = json.dumps(res_pt["findings"])
            self.assertNotIn(fake_key, serialized)
            self.assertIn("****", serialized)

            res_en = self.scanner.scan_directory(tmp, lang="en")
            self.assertEqual(res_en["category_labels"]["SECRETS"], "Security and credentials")
            self.assertGreaterEqual(collect_memory(trim_working_set=False), 0)

    def test_scan_and_env_reject_empty_target(self):
        res_empty_scan = self.client.post(
            "/api/scan",
            data=json.dumps({"target_dir": "", "lang": "pt"}),
            content_type="application/json",
        )
        self.assertEqual(res_empty_scan.status_code, 400)

        res_empty_env = self.client.post(
            "/api/check-python",
            data=json.dumps({"target_dir": "", "lang": "en"}),
            content_type="application/json",
        )
        self.assertEqual(res_empty_env.status_code, 400)

    def test_git_audit_and_autofix_in_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as ef:
                ef.write("APP_ENV=local\n")
            before = audit_git_protection(tmp, lang="pt")
            self.assertFalse(before["has_gitignore"])
            self.assertIn(".env", before["missing_patterns"])

            fixed = fix_gitignore(tmp, lang="en")
            self.assertEqual(fixed["status"], "success")
            self.assertEqual(fixed["audit"]["missing_patterns"], [])

    def test_security_controls_injection_ssrf_redos_and_traversal(self):
        with self.assertRaises(ValueError):
            run_safe_update("upgrade_package", package_name="pandas && calc.exe")
        with self.assertRaises(ValueError):
            run_safe_update("upgrade_python", target_python_series="3.13; whoami")
        with self.assertRaises(ValueError):
            prefs_mgr.update_github_repo_url("http://evil.example.com/user/repo")
        with self.assertRaises(ValueError):
            prefs_mgr.add_custom_rule({"id": "BAD-REDOS", "title": "ReDoS", "pattern": "(a+)+$"})

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PermissionError):
                with patch.dict(
                    "core.guardrail_generator.GUARDRAIL_TEMPLATES",
                    {"evil": {"relative_install_path": "../escape.txt", "content_pt": "x", "content_en": "x"}},
                ):
                    install_guardrail_to_project(tmp, "evil")

    def test_report_exporters_brand_guardrail_code_and_seconds(self):
        scan_pt = self.scanner.scan_directory(BASE_DIR, lang="pt")
        scan_en = self.scanner.scan_directory(BASE_DIR, lang="en")
        with patch("core.env_updater._fetch_json", side_effect=OSError("offline test")):
            env_pt = inspect_python_and_packages(BASE_DIR, lang="pt")

        html_pt = export_html_report(scan_pt, env_pt, lang="pt")
        self.assertIn("guardrail code", html_pt)
        md_pt = export_markdown_report(scan_pt, env_pt, lang="pt")
        self.assertIn("# guardrail code", md_pt)
        self.assertRegex(md_pt, r"\d+\.\d{2}s")

        html_en = export_html_report(scan_en, env_pt, lang="en")
        self.assertIn("guardrail code", html_en)
        md_en = export_markdown_report(scan_en, env_pt, lang="en")
        self.assertIn("# guardrail code", md_en)

        json_doc = json.loads(export_json_report(scan_pt, env_pt))
        self.assertEqual(json_doc["audit_summary"]["status"], "success")

    def test_toggle_rule_module_custom_rule_and_repo_updates(self):
        res_off = self.client.post(
            "/api/tests/toggle-rule",
            data=json.dumps({"rule_id": "DEP-LOCALHOST-REF", "enabled": False, "lang": "pt"}),
            content_type="application/json",
        )
        self.assertEqual(res_off.status_code, 200)
        self.assertGreaterEqual(res_off.get_json()["docs"]["disabled_tests"], 1)

        res_on = self.client.post(
            "/api/tests/toggle-rule",
            data=json.dumps({"rule_id": "DEP-LOCALHOST-REF", "enabled": True, "lang": "pt"}),
            content_type="application/json",
        )
        self.assertEqual(res_on.status_code, 200)
        self.assertEqual(res_on.get_json()["docs"]["disabled_tests"], 0)

        fake_manifest = {
            "modules": [
                {
                    "id": "pack-demo-remote",
                    "name": "Pacote remoto",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": "REMOTE-DEMO-1",
                            "title": "Token remoto de teste",
                            "pattern": r"REMOTE_SECRET\s*=\s*['\"][A-Za-z0-9]{8,}['\"]",
                            "severity": "HIGH",
                            "category": "SECRETS",
                        }
                    ],
                }
            ]
        }
        with patch("core.preferences_manager._fetch_github_json", return_value=fake_manifest):
            chk = self.client.post(
                "/api/tests/check-updates",
                data=json.dumps({"lang": "pt"}),
                content_type="application/json",
            )
            self.assertEqual(chk.status_code, 200)
            self.assertTrue(chk.get_json()["has_updates"])

            dl = self.client.post(
                "/api/tests/download-updates",
                data=json.dumps({"lang": "pt"}),
                content_type="application/json",
            )
            self.assertEqual(dl.status_code, 200)
            self.assertEqual(dl.get_json()["added_count"], 1)

    def test_flask_ui_endpoints_and_bilingual_skills(self):
        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 200)
        self.assertEqual(res_home.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res_home.headers.get("X-Frame-Options"), "SAMEORIGIN")
        home_html = res_home.get_data(as_text=True)
        self.assertIn("guardrail code", home_html)
        self.assertIn("0.00s", home_html)
        self.assertIn("confirmGitModal", home_html)
        self.assertIn("scanLoadingOverlay", home_html)
        self.assertNotIn("/asd-100", home_html)

        res_tests = self.client.get("/testes")
        self.assertEqual(res_tests.status_code, 200)
        tests_html = res_tests.get_data(as_text=True)
        self.assertIn("guardrail code", tests_html)
        self.assertIn("btnCheckRepoUpdates", tests_html)
        self.assertIn("btnDownloadRepoUpdates", tests_html)
        self.assertIn("https://github.com/suelio/guardrail-code", tests_html)

        res_custom_pt = self.client.post(
            "/api/build-custom-skill",
            data=json.dumps({"skill_slug": "meu-guard", "publish_keyword": "publicar", "pillars": ["deploy_lock"], "lang": "pt"}),
            content_type="application/json",
        )
        self.assertEqual(res_custom_pt.status_code, 200)
        self.assertIn("Bloqueio estrito de publicação", res_custom_pt.get_json()["content"])

        res_custom_en = self.client.post(
            "/api/build-custom-skill",
            data=json.dumps({"skill_slug": "my-guard", "publish_keyword": "publish now", "pillars": ["deploy_lock"], "lang": "en"}),
            content_type="application/json",
        )
        self.assertEqual(res_custom_en.status_code, 200)
        self.assertIn("Strict deploy confirmation", res_custom_en.get_json()["content"])


if __name__ == "__main__":
    unittest.main()
