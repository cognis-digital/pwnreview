"""Smoke tests for PWNREVIEW (stdlib unittest, no network)."""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwnreview import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    ValidationError,
    build_report,
    load_engagement,
    parse_yaml,
    render_html,
    render_markdown,
    severity_stats,
)
from pwnreview.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "engagement.yaml",
)

SAMPLE = """
client: Test Corp
title: Sample Test
findings:
  - id: A-1
    title: Critical bug
    severity: critical
    cvss: 9.1
    affected:
      - host-a
    description: |
      multi
      line
  - id: A-2
    title: Low bug
    severity: low
"""


class TestYaml(unittest.TestCase):
    def test_parse_nested_and_block(self):
        data = parse_yaml(SAMPLE)
        self.assertEqual(data["client"], "Test Corp")
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(data["findings"][0]["cvss"], 9.1)
        self.assertIn("multi\nline", data["findings"][0]["description"])
        self.assertEqual(data["findings"][0]["affected"], ["host-a"])


class TestEngine(unittest.TestCase):
    def test_load_and_sort(self):
        eng = load_engagement(SAMPLE)
        order = [f.id for f in eng.sorted_findings()]
        self.assertEqual(order, ["A-1", "A-2"])  # critical before low

    def test_stats(self):
        eng = load_engagement(SAMPLE)
        st = severity_stats(eng)
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["overall_posture"], "critical")
        self.assertEqual(st["counts"]["critical"], 1)
        self.assertGreater(st["risk_score"], 0)

    def test_renderers(self):
        eng = load_engagement(SAMPLE)
        md = render_markdown(eng)
        self.assertIn("# Sample Test", md)
        self.assertIn("Critical bug", md)
        htmlout = render_html(eng)
        self.assertIn("<html>", htmlout)
        self.assertIn("badge", htmlout)

    def test_report_payload(self):
        eng = load_engagement(SAMPLE)
        rep = build_report(eng)
        self.assertEqual(rep["tool"], "pwnreview")
        self.assertEqual(rep["stats"]["total"], 2)

    def test_invalid_severity(self):
        bad = "client: c\ntitle: t\nfindings:\n  - title: x\n    severity: oops\n"
        with self.assertRaises(ValidationError):
            load_engagement(bad)

    def test_missing_findings(self):
        with self.assertRaises(ValidationError):
            load_engagement("client: c\ntitle: t\n")

    def test_duplicate_id(self):
        bad = (
            "client: c\ntitle: t\nfindings:\n"
            "  - id: X\n    title: a\n    severity: low\n"
            "  - id: X\n    title: b\n    severity: low\n"
        )
        with self.assertRaises(ValidationError):
            load_engagement(bad)

    def test_cvss_out_of_range(self):
        bad = "client: c\ntitle: t\nfindings:\n  - title: x\n    severity: low\n    cvss: 99\n"
        with self.assertRaises(ValidationError):
            load_engagement(bad)


class TestCli(unittest.TestCase):
    def test_demo_exists(self):
        self.assertTrue(os.path.exists(DEMO))

    def test_generate_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["generate", DEMO, "--format", "json"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["stats"]["overall_posture"], "critical")
        self.assertEqual(payload["engagement"]["findings"][0]["severity"], "critical")

    def test_validate_table(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["validate", DEMO])
        self.assertEqual(rc, 0)
        self.assertIn("OK", buf.getvalue())

    def test_validate_failure_exit(self):
        bad = os.path.join(os.path.dirname(__file__), "_bad.yaml")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("client: c\ntitle: t\n")  # no findings
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["validate", bad, "--format", "json"])
            self.assertEqual(rc, 1)
            self.assertFalse(json.loads(buf.getvalue())["ok"])
        finally:
            os.remove(bad)

    def test_missing_file(self):
        rc = main(["generate", "/nonexistent/path.yaml"])
        self.assertEqual(rc, 2)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "pwnreview")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
