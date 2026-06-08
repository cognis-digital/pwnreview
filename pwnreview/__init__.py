"""PWNREVIEW - Pentest report generator: YAML findings -> CREST-grade report.

Standard-library only, zero install. Parses an engagement YAML (subset parser
bundled), validates findings, computes CVSS-ish severity ordering and risk
stats, and renders a self-contained report (HTML/Markdown) plus machine JSON.
"""
from .core import (
    Engagement,
    Finding,
    SEVERITIES,
    load_engagement,
    parse_yaml,
    build_report,
    render_html,
    render_markdown,
    severity_stats,
    ValidationError,
)

TOOL_NAME = "pwnreview"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Engagement",
    "Finding",
    "SEVERITIES",
    "load_engagement",
    "parse_yaml",
    "build_report",
    "render_html",
    "render_markdown",
    "severity_stats",
    "ValidationError",
]
