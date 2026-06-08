"""Command-line interface for PWNREVIEW."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ValidationError,
    build_report,
    load_engagement,
    render_html,
    render_markdown,
    severity_stats,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _print_table(stats: dict, eng) -> None:
    print(f"Engagement : {eng.title}")
    print(f"Client     : {eng.client}")
    print(f"Findings   : {stats['total']}")
    print(f"Posture    : {stats['overall_posture'].upper()}  (score {stats['risk_score']})")
    print("-" * 40)
    for sev, n in stats["counts"].items():
        print(f"  {sev.capitalize():<9}: {n}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Pentest report generator: YAML findings -> CREST-grade report.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="validate engagement YAML and render a report")
    gen.add_argument("input", help="engagement YAML file ('-' for stdin)")
    gen.add_argument("--format", choices=["table", "json"], default="table",
                     help="console output format (default: table)")
    gen.add_argument("--render", choices=["html", "markdown", "none"], default="none",
                     help="also render a full report document")
    gen.add_argument("-o", "--output", help="write rendered document to file")

    val = sub.add_parser("validate", help="validate engagement YAML only")
    val.add_argument("input", help="engagement YAML file ('-' for stdin)")
    val.add_argument("--format", choices=["table", "json"], default="table")

    args = parser.parse_args(argv)

    try:
        eng = load_engagement(_read(args.input))
    except FileNotFoundError:
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        if getattr(args, "format", "table") == "json":
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    stats = severity_stats(eng)

    if args.command == "validate":
        if args.format == "json":
            print(json.dumps({"ok": True, "stats": stats}, indent=2))
        else:
            print(f"OK: {stats['total']} valid finding(s); posture {stats['overall_posture'].upper()}")
        return 0

    # generate
    rendered = None
    if args.render == "html":
        rendered = render_html(eng)
    elif args.render == "markdown":
        rendered = render_markdown(eng)

    if rendered is not None:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        else:
            sys.stdout.write(rendered)
            if not rendered.endswith("\n"):
                sys.stdout.write("\n")
            return 0

    if args.format == "json":
        print(json.dumps(build_report(eng), indent=2))
    else:
        _print_table(stats, eng)
        if args.output and rendered is not None:
            print(f"\nWrote {args.render} report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
