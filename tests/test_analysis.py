import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from ghost_trace_lite.evidence import auth_event, flow_event, load_auth, utc_timestamp
from ghost_trace_lite.ghost_trace import inspect_ioc, normalize_domain, virustotal_lookup
from ghost_trace_lite.phantom_hunter import correlate
from ghost_trace_lite.sentinel import alert_record, detect_failed_logins
from ghost_trace_lite.shadow_proxy import inspect_headers
from ghost_trace_lite.shadow_recon import check_scope, load_scope


def login(row, clock, outcome="failure", user="analyst", source="192.0.2.1"):
    return auth_event(row, {
        "timestamp": f"2026-01-15T{clock}Z",
        "user": user,
        "host": "ws-1",
        "host_ip": "10.0.0.17",
        "src_ip": source,
        "outcome": outcome,
    })


def flow(row, clock, source="10.0.0.17"):
    return flow_event(row, {
        "timestamp": f"2026-01-15T{clock}Z",
        "src_ip": source,
        "dst_ip": "198.51.100.23",
        "dst_port": "443",
        "protocol": "tcp",
        "bytes": "1",
    })


class TestIndicators(unittest.TestCase):
    def test_normalizes_ipv6_and_domains(self):
        self.assertEqual(inspect_ioc(" 2001:0DB8::1 ")["value"], "2001:db8::1")
        self.assertEqual(inspect_ioc(" UPDATES.Ronin.Test. "), {
            "value": "updates.ronin.test", "type": "domain",
        })

    def test_rejects_invalid_indicators(self):
        for value in ("", "http://ronin.test", "ronin", "a..test", "-a.test", "a-.test",
                      "a.test..", "256.0.0.1", "fe80::1%eth0", "bad_label.test", "a" * 64 + ".test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inspect_ioc(value)

    def test_checks_total_domain_length(self):
        self.assertEqual(len(normalize_domain(".".join(["a" * 63] * 3 + ["b" * 61]))), 253)
        with self.assertRaises(ValueError):
            normalize_domain(".".join(["a" * 63] * 3 + ["b" * 62]))

    def test_ip_scopes(self):
        cases = {
            "8.8.8.8": "public", "1.1.1.1": "public", "192.168.1.1": "private",
            "fd00::1": "private", "198.51.100.9": "documentation", "2001:db8::1": "documentation",
            "100.64.0.1": "shared_address_space", "127.0.0.1": "loopback", "fe80::1": "link_local",
            "224.0.0.1": "multicast", "::": "unspecified", "::ffff:10.0.0.1": "private",
        }
        for value, scope in cases.items():
            with self.subTest(value=value):
                self.assertEqual(inspect_ioc(value)["scope"], scope)

    def test_wildcard_requires_a_dot_boundary_and_excludes_apex(self):
        rules = ["*.ronin.test"]
        for value in ("ronin.test", "notronin.test", "a.ronin.test.other"):
            self.assertFalse(check_scope(value, rules)["in_scope"])
        self.assertTrue(check_scope("A.B.RONIN.TEST.", rules)["in_scope"])
        self.assertTrue(check_scope("ronin.test", ["ronin.test", *rules])["in_scope"])


class TestVirusTotal(unittest.TestCase):
    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_local_indicators_and_missing_key_do_not_open_connections(self, opener):
        for value in ("10.0.0.1", "2001:db8::1", "x.ronin.test", "sub.example.com"):
            self.assertEqual(virustotal_lookup(inspect_ioc(value), "mock-key")["status"], "skipped")
        self.assertEqual(virustotal_lookup(inspect_ioc("8.8.8.8"), "")["status"], "error")
        opener.assert_not_called()

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_ip_and_domain_reports(self, opener):
        for value, endpoint in [("8.8.8.8", "ip_addresses"), ("python.org", "domains")]:
            body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 23},
                                           "unneeded": "omit-this"}}}
            opener.return_value.open.return_value = io.BytesIO(json.dumps(body).encode())
            result = virustotal_lookup(inspect_ioc(value), "mock-key")
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, f"https://www.virustotal.com/api/v3/{endpoint}/{value}")
            self.assertEqual(request.get_header("X-apikey"), "mock-key")
            self.assertEqual(result, {"status": "ok", "last_analysis_stats": {"malicious": 1, "harmless": 23}})
            self.assertIsNone(opener.call_args.args[0].redirect_request(None, None, 302, "", {}, "https://other.test"))

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_rate_limit_and_not_found(self, opener):
        for code, status in ((429, "error"), (404, "not_found"), (302, "error"), (401, "error")):
            opener.return_value.open.side_effect = HTTPError("", code, "ignore body", {}, io.BytesIO())
            result = virustotal_lookup(inspect_ioc("8.8.8.8"), "mock-key")
            self.assertEqual(result["status"], status)
            self.assertNotIn("ignore body", result["message"])

    @patch("ghost_trace_lite.ghost_trace.build_opener")
    def test_malformed_response_and_network_error(self, opener):
        opener.return_value.open.return_value = io.BytesIO(b'{"data": null}')
        self.assertEqual(virustotal_lookup(inspect_ioc("8.8.8.8"), "mock-key")["status"], "error")
        opener.return_value.open.side_effect = URLError("do not echo raw error")
        result = virustotal_lookup(inspect_ioc("8.8.8.8"), "mock-key")
        self.assertEqual(result["status"], "error")
        self.assertNotIn("raw error", result["message"])


class TestCorrelation(unittest.TestCase):
    def test_threshold_uses_inclusive_window_and_evidence_ids(self):
        events = [login(2, "14:00:00"), login(3, "14:02:00"), login(4, "14:05:00")]
        alerts = detect_failed_logins(events)
        self.assertEqual([alert_record(alert)["evidence_ids"] for alert in alerts],
                         [["auth:2", "auth:3", "auth:4"]])
        self.assertEqual(detect_failed_logins(events[:2] + [login(4, "14:05:01")]), [])

    def test_success_and_other_sources_do_not_complete_a_burst(self):
        events = [login(2, "14:00:00"), login(3, "14:01:00", "success"),
                  login(4, "14:02:00"), login(5, "14:03:00", source="192.0.2.8"),
                  login(6, "14:04:00", user="other")]
        self.assertEqual(detect_failed_logins(events), [])

    def test_hunt_uses_matching_success_and_only_later_same_host_flows(self):
        events = [
            login(2, "14:00:00"), login(3, "14:01:00"), login(4, "14:02:00"),
            login(5, "14:03:00", "success", user="other"),
            login(6, "14:12:00", "success"),
        ]
        flows = [flow(2, "14:11:00"), flow(3, "14:12:00"), flow(4, "14:13:00", "10.0.0.18"),
                 flow(5, "14:22:00"), flow(6, "14:22:01")]
        result = correlate(detect_failed_logins(events), events, flows)
        self.assertEqual(result["correlations"], [{
            "alert_id": "failed-logins:4", "success_evidence_id": "auth:6", "flow_evidence_ids": ["flow:5"],
        }])
        self.assertEqual([event["id"] for event in result["timeline"]],
                         ["auth:2", "auth:3", "auth:4", "auth:6", "flow:5"])

    def test_unmatched_success_produces_no_correlation(self):
        events = [login(2, "14:00:00"), login(3, "14:01:00"), login(4, "14:02:00"),
                  login(5, "14:12:01", "success")]
        self.assertEqual(correlate(detect_failed_logins(events), events, [])["timeline"], [])

    def test_explicit_offsets_are_converted_to_utc(self):
        self.assertEqual(utc_timestamp("2026-01-15T07:00:00-07:00").isoformat(), "2026-01-15T14:00:00+00:00")
        with self.assertRaises(ValueError):
            utc_timestamp("2026-01-15T07:00:00")


class TestEvidenceFiles(unittest.TestCase):
    def test_header_redaction_and_duplicate_headers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "headers.txt"
            path.write_text(
                "GET /q?key=secret-query HTTP/1.1\r\n"
                "Host: [2001:db8::1]:8443\r\nContent-Type: application/json; x=secret-param\r\n"
                "AUTHORIZATION: Bearer secret-auth\r\nCookie: secret-cookie\r\ncookie: second\r\n"
                "X-Session-Token: secret-custom\r\n\r\nsecret-body",
                encoding="utf-8",
            )
            result = inspect_headers(path)
            self.assertEqual(result["method"], "GET")
            self.assertEqual([header["value"] for header in result["headers"]],
                             ["[2001:db8::1]:8443", "application/json"] + ["[redacted]"] * 4)
            self.assertEqual([header["name"] for header in result["headers"]].count("cookie"), 2)
            self.assertNotIn("secret", json.dumps(result))

    def test_malformed_rows_include_file_and_line(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            auth = root / "auth.csv"
            auth.write_text("timestamp,user,host,host_ip,src_ip,outcome\n"
                            "2026-01-15T14:00:00Z,analyst,ws-1,10.0.0.1,192.0.2.1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"auth\.csv:2: unexpected number of columns"):
                load_auth(auth)
            scope = root / "scope.txt"
            scope.write_text("# comment\n*.bad..test\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"scope\.txt:2: invalid scope rule"):
                load_scope(scope)

    def test_rejects_folded_headers_without_disclosing_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "headers.txt"
            path.write_text("Authorization: token\n secret-continuation\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"^headers\.txt:2: expected a header name and colon$"):
                inspect_headers(path)
