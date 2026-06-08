"""Core engine for PWNREVIEW.

No third-party deps. Includes a small but real YAML subset parser (enough for
flat keys, nested maps, block lists, and lists-of-maps) so engagements can be
authored in standard YAML without PyYAML installed.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# CREST/CVSS-aligned ordering, highest risk first.
SEVERITIES = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Numeric weight used for an aggregate risk score (CVSS-band midpoints).
_SEV_WEIGHT = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


class ValidationError(Exception):
    """Raised when an engagement document is malformed or incomplete."""


# --------------------------------------------------------------------------- #
# Minimal YAML subset parser
# --------------------------------------------------------------------------- #
def _strip_comment(line: str) -> str:
    out, in_s, in_d = [], False, False
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            break
        out.append(ch)
    return "".join(out)


def _scalar(tok: str) -> Any:
    tok = tok.strip()
    if tok == "" or tok in ("~", "null", "Null", "NULL"):
        return None
    if (tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'"):
        return tok[1:-1]
    low = tok.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    return tok


def parse_yaml(text: str) -> Any:
    """Parse a useful YAML subset into Python data structures."""
    lines = []
    for raw in text.splitlines():
        body = _strip_comment(raw).rstrip()
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        lines.append((indent, body.strip()))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        # Decide list vs map by first child token.
        if pos >= len(lines):
            return None
        cur_indent, cur = lines[pos]
        if cur.startswith("- ") or cur == "-":
            return parse_list(cur_indent)
        return parse_map(cur_indent)

    def parse_list(indent: int):
        nonlocal pos
        items = []
        while pos < len(lines):
            ci, c = lines[pos]
            if ci < indent or not (c.startswith("- ") or c == "-"):
                break
            rest = c[2:].strip() if c != "-" else ""
            if rest == "":
                pos += 1
                items.append(parse_block(indent + 1))
            elif ":" in rest and not _looks_like_scalar(rest):
                # inline first key of a map item; rewrite line then parse map
                lines[pos] = (indent + 2, rest)
                items.append(parse_map(indent + 2))
            else:
                pos += 1
                items.append(_scalar(rest))
        return items

    def parse_map(indent: int):
        nonlocal pos
        obj: dict = {}
        while pos < len(lines):
            ci, c = lines[pos]
            if ci < indent:
                break
            if ci > indent:
                break
            if c.startswith("- "):
                break
            key, _, val = c.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val == "":
                # nested block (map or list) or null
                if pos < len(lines) and lines[pos][0] > indent:
                    obj[key] = parse_block(indent + 1)
                elif pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
                    obj[key] = parse_list(indent)
                else:
                    obj[key] = None
            elif val == "|" or val == ">":
                obj[key] = _parse_block_scalar(indent, fold=(val == ">"))
            else:
                obj[key] = _scalar(val)
        return obj

    def _parse_block_scalar(indent: int, fold: bool):
        nonlocal pos
        collected = []
        base = None
        while pos < len(lines):
            ci, c = lines[pos]
            if ci <= indent:
                break
            if base is None:
                base = ci
            collected.append(" " * (ci - base) + c)
            pos += 1
        return (" ".join(collected) if fold else "\n".join(collected))

    def _looks_like_scalar(rest: str) -> bool:
        # "- http://x" style: colon present but it's a URL/scalar, not a key.
        key = rest.split(":", 1)[0]
        return " " in key or "/" in key

    result = parse_block(0)
    return result if result is not None else {}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str = ""
    impact: str = ""
    remediation: str = ""
    affected: list = field(default_factory=list)
    cvss: float | None = None
    references: list = field(default_factory=list)

    @property
    def rank(self) -> int:
        return _SEV_RANK.get(self.severity, len(SEVERITIES))

    @property
    def weight(self) -> float:
        if self.cvss is not None:
            return float(self.cvss)
        return _SEV_WEIGHT.get(self.severity, 0.0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "cvss": self.cvss,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "affected": list(self.affected),
            "references": list(self.references),
        }


@dataclass
class Engagement:
    client: str
    title: str
    findings: list
    consultant: str = ""
    date: str = ""
    scope: list = field(default_factory=list)

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: (f.rank, -f.weight, f.id))

    def to_dict(self) -> dict:
        return {
            "client": self.client,
            "title": self.title,
            "consultant": self.consultant,
            "date": self.date,
            "scope": list(self.scope),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def load_engagement(text: str) -> Engagement:
    """Parse + validate an engagement YAML document into an Engagement."""
    data = parse_yaml(text)
    if not isinstance(data, dict):
        raise ValidationError("top-level YAML must be a mapping")
    for req in ("client", "title"):
        if not data.get(req):
            raise ValidationError(f"missing required field: {req}")
    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list) or not raw_findings:
        raise ValidationError("engagement must contain a non-empty 'findings' list")

    findings, seen_ids = [], set()
    for i, rf in enumerate(raw_findings, 1):
        if not isinstance(rf, dict):
            raise ValidationError(f"finding #{i} is not a mapping")
        fid = str(rf.get("id") or f"F-{i:03d}")
        if fid in seen_ids:
            raise ValidationError(f"duplicate finding id: {fid}")
        seen_ids.add(fid)
        sev = str(rf.get("severity", "")).strip().lower()
        if sev not in _SEV_RANK:
            raise ValidationError(
                f"finding {fid}: invalid severity {sev!r} (use {', '.join(SEVERITIES)})"
            )
        if not rf.get("title"):
            raise ValidationError(f"finding {fid}: missing title")
        cvss = rf.get("cvss")
        if cvss is not None:
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                raise ValidationError(f"finding {fid}: cvss must be numeric")
            if not 0.0 <= cvss <= 10.0:
                raise ValidationError(f"finding {fid}: cvss out of range 0-10")
        findings.append(
            Finding(
                id=fid,
                title=str(rf["title"]),
                severity=sev,
                description=str(rf.get("description", "") or ""),
                impact=str(rf.get("impact", "") or ""),
                remediation=str(rf.get("remediation", "") or ""),
                affected=[str(a) for a in _as_list(rf.get("affected"))],
                cvss=cvss,
                references=[str(r) for r in _as_list(rf.get("references"))],
            )
        )

    return Engagement(
        client=str(data["client"]),
        title=str(data["title"]),
        findings=findings,
        consultant=str(data.get("consultant", "") or ""),
        date=str(data.get("date", "") or ""),
        scope=[str(s) for s in _as_list(data.get("scope"))],
    )


# --------------------------------------------------------------------------- #
# Analytics
# --------------------------------------------------------------------------- #
def severity_stats(eng: Engagement) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in eng.findings:
        counts[f.severity] += 1
    total = len(eng.findings)
    risk_score = round(sum(f.weight for f in eng.findings), 2)
    # Highest severity present drives overall posture.
    posture = "info"
    for s in SEVERITIES:
        if counts[s]:
            posture = s
            break
    return {
        "total": total,
        "counts": counts,
        "risk_score": risk_score,
        "overall_posture": posture,
    }


def build_report(eng: Engagement) -> dict:
    """Assemble the full machine-readable report payload."""
    return {
        "tool": "pwnreview",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "engagement": eng.to_dict(),
        "stats": severity_stats(eng),
    }


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def render_markdown(eng: Engagement) -> str:
    st = severity_stats(eng)
    out = [f"# {eng.title}", ""]
    out.append(f"**Client:** {eng.client}  ")
    if eng.consultant:
        out.append(f"**Consultant:** {eng.consultant}  ")
    if eng.date:
        out.append(f"**Date:** {eng.date}  ")
    out.append("")
    if eng.scope:
        out.append("## Scope")
        out += [f"- {s}" for s in eng.scope] + [""]
    out.append("## Executive Summary")
    out.append(
        f"{st['total']} finding(s) identified. Overall risk posture: "
        f"**{st['overall_posture'].upper()}** (aggregate score {st['risk_score']})."
    )
    out.append("")
    out.append("| Severity | Count |")
    out.append("|----------|-------|")
    for s in SEVERITIES:
        out.append(f"| {s.capitalize()} | {st['counts'][s]} |")
    out.append("")
    out.append("## Findings")
    for f in eng.sorted_findings():
        cvss = f" (CVSS {f.cvss})" if f.cvss is not None else ""
        out.append(f"### [{f.severity.upper()}] {f.id}: {f.title}{cvss}")
        if f.affected:
            out.append(f"**Affected:** {', '.join(f.affected)}  ")
        if f.description:
            out += ["", "**Description**", "", f.description]
        if f.impact:
            out += ["", "**Impact**", "", f.impact]
        if f.remediation:
            out += ["", "**Remediation**", "", f.remediation]
        if f.references:
            out += ["", "**References**"] + [f"- {r}" for r in f.references]
        out.append("")
    return "\n".join(out)


_SEV_COLOR = {
    "critical": "#7b1fa2",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#2e7d32",
    "info": "#1565c0",
}


def render_html(eng: Engagement) -> str:
    e = html.escape
    st = severity_stats(eng)
    rows = "".join(
        f'<tr><td><span class="badge" style="background:{_SEV_COLOR[s]}">'
        f"{s.capitalize()}</span></td><td>{st['counts'][s]}</td></tr>"
        for s in SEVERITIES
    )
    blocks = []
    for f in eng.sorted_findings():
        cvss = f" &middot; CVSS {f.cvss}" if f.cvss is not None else ""
        parts = [
            f'<div class="finding">',
            f'<h3><span class="badge" style="background:{_SEV_COLOR[f.severity]}">'
            f"{f.severity.upper()}</span> {e(f.id)}: {e(f.title)}{cvss}</h3>",
        ]
        if f.affected:
            parts.append(f"<p><b>Affected:</b> {e(', '.join(f.affected))}</p>")
        for label, val in (
            ("Description", f.description),
            ("Impact", f.impact),
            ("Remediation", f.remediation),
        ):
            if val:
                parts.append(f"<p><b>{label}</b><br>{e(val)}</p>")
        if f.references:
            refs = "".join(f"<li>{e(r)}</li>" for r in f.references)
            parts.append(f"<p><b>References</b></p><ul>{refs}</ul>")
        parts.append("</div>")
        blocks.append("".join(parts))
    scope = "".join(f"<li>{e(s)}</li>" for s in eng.scope)
    return f"""<!doctype html><html><head><meta charset=\"utf-8\">
<title>{e(eng.title)}</title><style>
body{{font-family:Arial,Helvetica,sans-serif;margin:2rem;color:#222;max-width:60rem}}
h1{{border-bottom:3px solid #111}}
.badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.8em}}
table{{border-collapse:collapse}}td{{border:1px solid #ccc;padding:4px 10px}}
.finding{{border-left:4px solid #999;padding:0 1rem;margin:1rem 0}}
</style></head><body>
<h1>{e(eng.title)}</h1>
<p><b>Client:</b> {e(eng.client)}<br>
<b>Consultant:</b> {e(eng.consultant)}<br><b>Date:</b> {e(eng.date)}</p>
{('<h2>Scope</h2><ul>' + scope + '</ul>') if scope else ''}
<h2>Executive Summary</h2>
<p>{st['total']} finding(s). Overall posture:
<b>{st['overall_posture'].upper()}</b> (aggregate score {st['risk_score']}).</p>
<table>{rows}</table>
<h2>Findings</h2>
{''.join(blocks)}
</body></html>"""
