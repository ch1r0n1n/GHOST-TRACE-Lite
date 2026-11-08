import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

from ghost_trace_lite.cli import main
from ghost_trace_lite.enrichment import enrich_indicator
from ghost_trace_lite.ghost_trace import inspect_ioc


class TestInteractiveMenu(unittest.TestCase):
    def test_launcher_routes_all_ten_tools_and_demo(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case = root / "menu case"
            demo = root / "menu demo"
            inputs = [
                "1", "192.0.2.44", "",
                "2", "updates.ronin.test", "",
                "3", "", "4", "", "5", "", "",
                "6", "", "7", "", "", "8", "",
                "9", "", f'"{case}"', "10", "",
                "11", str(demo), "0",
            ]
            run = subprocess.run(
                [sys.executable, "main.py"], input="\n".join(inputs) + "\n",
                capture_output=True, text=True, encoding="utf-8", check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, "")
            for value in ("documentation", '"in_scope": true', "failed-logins:4", '"flow_count": 5',
                          "auth:5", "3 failed logins", "flowchart TD", "[redacted]", "Check MFA"):
                self.assertIn(value, run.stdout)
            self.assertTrue((case / "case.json").is_file())
            self.assertTrue((demo / "relationships.mmd").is_file())

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    @patch("ghost_trace_lite.menu.getpass.getpass", return_value="sample-session-secret")
    def test_session_key_precedence_decline_clear_and_environment_fallback(self, masked_input, opener):
        def provider_response(*args, **kwargs):
            return io.BytesIO(b'{"pulse_info":{"count":5}}')

        opener.return_value.open.side_effect = provider_response
        inputs = [
            "12", "3", "s",
            "1", "python.org", "3", "n",
            "1", "python.org", "3", "y",
            "12", "3", "c",
            "1", "python.org", "3", "y",
            "0",
        ]
        output = io.StringIO()
        with patch.dict(os.environ, {"OTX_API_KEY": "sample-env-secret"}):
            with patch("builtins.input", side_effect=inputs), contextlib.redirect_stdout(output):
                self.assertEqual(main(["menu"]), 0)
            self.assertEqual(os.environ["OTX_API_KEY"], "sample-env-secret")
        masked_input.assert_called_once()
        self.assertEqual(opener.return_value.open.call_count, 2)
        requests = [call.args[0] for call in opener.return_value.open.call_args_list]
        self.assertEqual([request.get_header("X-otx-api-key") for request in requests],
                         ["sample-session-secret", "sample-env-secret"])
        self.assertIn('"pulse_count": 5', output.getvalue())
        self.assertNotIn("sample-session-secret", output.getvalue())
        self.assertNotIn("sample-env-secret", output.getvalue())

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_virustotal_flag_keeps_legacy_result_key(self, opener):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["ioc", "10.0.0.1", "--virustotal"]), 0)
        self.assertEqual(json.loads(output.getvalue())["virustotal"]["status"], "skipped")
        opener.assert_not_called()


class TestAdditionalProviders(unittest.TestCase):
    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_shodan_host_lookup_encodes_key_and_returns_only_summary_fields(self, opener):
        opener.return_value.open.return_value = io.BytesIO(
            b'{"ports":[443,53,53,-1,true],"org":"Sample","data":[{"banner":"omit"}]}'
        )
        result = enrich_indicator(inspect_ioc("8.8.8.8"), "shodan", "test+key")
        request = opener.return_value.open.call_args.args[0]
        url = urlsplit(request.full_url)
        self.assertEqual((url.scheme, url.netloc, url.path), ("https", "api.shodan.io", "/shodan/host/8.8.8.8"))
        self.assertEqual(parse_qs(url.query), {"key": ["test+key"], "minify": ["true"]})
        self.assertEqual(result, {"status": "ok", "ports": [53, 443], "org": "Sample"})

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_otx_lookup_uses_indicator_type_and_header(self, opener):
        opener.return_value.open.return_value = io.BytesIO(b'{"pulse_info":{"count":3}}')
        result = enrich_indicator(inspect_ioc("2001:4860:4860::8888"), "otx", "test-key")
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url,
                         "https://otx.alienvault.com/api/v1/indicators/IPv6/2001%3A4860%3A4860%3A%3A8888/general")
        self.assertEqual(request.get_header("X-otx-api-key"), "test-key")
        self.assertEqual(result, {"status": "ok", "pulse_count": 3})

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_nonpublic_or_unsupported_inputs_do_not_connect(self, opener):
        self.assertEqual(enrich_indicator(inspect_ioc("python.org"), "shodan", "test")["status"], "skipped")
        self.assertEqual(enrich_indicator(inspect_ioc("10.0.0.1"), "shodan", "test")["status"], "skipped")
        self.assertEqual(enrich_indicator(inspect_ioc("site.test"), "otx", "test")["status"], "skipped")
        self.assertEqual(enrich_indicator(inspect_ioc("python.org"), "otx", "bad\nkey")["status"], "error")
        opener.assert_not_called()

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_network_errors_hide_request_details(self, opener):
        opener.return_value.open.side_effect = URLError("request URL contained test-secret")
        result = enrich_indicator(inspect_ioc("8.8.8.8"), "shodan", "test-secret")
        self.assertEqual(result["status"], "error")
        self.assertNotIn("test-secret", json.dumps(result))
