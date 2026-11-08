import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghost_trace_lite.cli import DEMO_DIR
from ghost_trace_lite.ronin_soc import build_case, export_case


class TestCLI(unittest.TestCase):
    def run_cli(self, *arguments, code=0):
        result = subprocess.run(
            [sys.executable, "-m", "ghost_trace_lite", *map(str, arguments)],
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_demo_runs_all_modules_and_exports_a_consistent_case(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "new-case"
            summary = json.loads(self.run_cli("demo", "--out", output).stdout)
            self.assertEqual(summary["alerts"], 1)
            self.assertEqual(summary["correlated_logins"], 1)
            self.assertEqual(sorted(path.name for path in output.iterdir()),
                             ["case.json", "case.md", "relationships.mmd"])

            case_text = (output / "case.json").read_text(encoding="utf-8")
            case = json.loads(case_text)
            report = (output / "case.md").read_text(encoding="utf-8")
            graph = (output / "relationships.mmd").read_text(encoding="utf-8")
            self.assertEqual(case["hunt"]["correlations"][0]["flow_evidence_ids"], ["flow:4", "flow:5"])
            self.assertEqual(case["traffic"]["total_bytes"], 20374)
            self.assertTrue(case["indicators"])
            self.assertEqual(case["explanations"][0]["evidence_ids"], ["auth:2", "auth:3", "auth:4"])
            self.assertTrue(any(not check["in_scope"] for check in case["scope_checks"]))
            self.assertTrue(any(step["evidence_ids"] == ["flow:4", "flow:5"] for step in case["next_steps"]))
            self.assertIn("updates.ronin.test", graph)
            self.assertIn(graph, report)
            for sample_secret in ("synthetic-auth", "synthetic-session", "synthetic-key",
                                  "synthetic-query", "synthetic-parameter", "SyntheticLab"):
                self.assertNotIn(sample_secret, case_text + report + graph)
            self.run_cli("demo", "--out", output, code=2)
            self.assertEqual((output / "case.json").read_text(encoding="utf-8"), case_text)

    def test_each_module_command_has_usable_output(self):
        auth = DEMO_DIR / "auth.csv"
        flows = DEMO_DIR / "flows.csv"
        rules = DEMO_DIR / "scope.txt"
        commands = [
            (("ioc", "192.0.2.44"), "documentation"),
            (("scope", "updates.ronin.test", "--rules", rules), '"in_scope": true'),
            (("detect", auth), "failed-logins:4"),
            (("traffic", flows), '"flow_count": 5'),
            (("hunt", auth, flows), "auth:5"),
            (("explain", auth), "3 failed logins"),
            (("map", auth, flows), "flowchart TD"),
            (("headers", DEMO_DIR / "headers.txt"), "[redacted]"),
            (("advise", DEMO_DIR), "Check MFA"),
        ]
        for args, marker in commands:
            with self.subTest(command=args[0]):
                self.assertIn(marker, self.run_cli(*args).stdout)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "investigation"
            self.run_cli("investigate", DEMO_DIR, "--out", output, "--threshold", 4)
            case = json.loads((output / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(case["alerts"], [])

    def test_exit_codes_and_usage_errors(self):
        self.assertIn("expected a dotted ASCII hostname", self.run_cli("ioc", "bad..domain", code=2).stderr)
        self.assertIn('"in_scope": false', self.run_cli(
            "scope", "notronin.test", "--rules", DEMO_DIR / "scope.txt", code=1).stdout)
        self.assertIn("expected an integer", self.run_cli(
            "detect", DEMO_DIR / "auth.csv", "--window", "0", code=2).stderr)

    def test_case_export_cleans_up_a_failed_write(self):
        case = build_case(DEMO_DIR)
        write_text = Path.write_text

        def fail_second_write(path, *args, **kwargs):
            if path.name == "case.md":
                raise OSError("simulated write failure")
            return write_text(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "failed-case"
            with patch.object(Path, "write_text", fail_second_write):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    export_case(case, output)
            self.assertFalse(output.exists())
            export_case(case, output)
            self.assertTrue((output / "case.json").exists())
