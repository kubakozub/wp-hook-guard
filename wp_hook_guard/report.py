"""Rendering: human-readable table, JSON, and version-diff output."""

from __future__ import annotations

import json
import os

from .model import SEV_RANK, SEVERITIES, VERDICTS

_REACH_ORDER = {"unauthenticated": 0, "authenticated": 1, "unknown": 2}
_REACH_SHORT = {"unauthenticated": "unauth", "authenticated": "auth", "unknown": "unknown"}

_ANSI = {
    "CRITICAL": "\033[1;35m",  # bold magenta
    "HIGH": "\033[1;31m",      # bold red
    "MEDIUM": "\033[33m",      # yellow
    "LOW": "\033[36m",         # cyan
    "INFO": "\033[2m",         # dim
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

_VERDICT_ANSI = {
    "UNGUARDED": "\033[1;31m",
    "WEAK": "\033[33m",
    "UNKNOWN": "\033[35m",
    "GUARDED": "\033[32m",
}


def sort_key(f):
    return (SEV_RANK.get(f.severity, 99), _REACH_ORDER.get(f.reach, 9), f.file, f.line)


def _rel(path, root):
    try:
        base = root if os.path.isdir(root) else os.path.dirname(root)
        rel = os.path.relpath(path, base or ".")
        return rel if not rel.startswith("..") else path
    except ValueError:
        return path


def _c(text, key, use_color):
    if not use_color:
        return text
    return _ANSI.get(key, "") + text + _ANSI["reset"]


def _cv(text, verdict, use_color):
    if not use_color:
        return text
    return _VERDICT_ANSI.get(verdict, "") + text + _ANSI["reset"]


def _trunc(s, width):
    s = s if s else "-"
    return s if len(s) <= width else s[: width - 1] + "…"


def render_table(result, use_color=False, only_unguarded=False, min_severity=None):
    findings = _filter(result.findings, only_unguarded, min_severity)
    findings = sorted(findings, key=sort_key)
    lines = []
    if not findings:
        lines.append("No entry points matched the current filters.")
        lines.append("")
        lines.append(render_summary(result, use_color))
        return "\n".join(lines)

    # Column widths (content-aware, with sane caps).
    rows = []
    for f in findings:
        rows.append(
            [
                f.severity,
                f.verdict,
                _REACH_SHORT.get(f.reach, f.reach),
                f.kind,
                _trunc(f.target, 40),
                _trunc(",".join(f.guards) if f.guards else "-", 34),
                _rel(f.file, result.root) + ":" + str(f.line),
            ]
        )
    headers = ["SEVERITY", "VERDICT", "REACH", "KIND", "ACTION / ROUTE", "GUARDS", "LOCATION"]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells, colorize=None):
        out = []
        for i, cell in enumerate(cells):
            padded = cell.ljust(widths[i])
            if colorize:
                padded = colorize(i, cell, padded)
            out.append(padded)
        return "  ".join(out).rstrip()

    lines.append(_c(fmt_row(headers), "bold", use_color))
    lines.append("  ".join("-" * w for w in widths))
    for f, r in zip(findings, rows):
        def colorize(i, cell, padded, _f=f):
            if i == 0:
                return _c(padded, _f.severity, use_color)
            if i == 1:
                return _cv(padded, _f.verdict, use_color)
            return padded
        lines.append(fmt_row(r, colorize))

    lines.append("")
    lines.append(render_summary(result, use_color))
    return "\n".join(lines)


def render_summary(result, use_color=False):
    by_sev, by_verdict = result.counts()
    total = len(result.findings)
    parts = []
    parts.append(
        "Scanned %d file(s); found %d entry point(s)."
        % (result.stats.files_scanned, total)
    )
    sev_bits = []
    for s in SEVERITIES:
        if by_sev.get(s):
            sev_bits.append(_c("%s=%d" % (s, by_sev[s]), s, use_color))
    if sev_bits:
        parts.append("Severity: " + "  ".join(sev_bits))
    ver_bits = []
    for v in VERDICTS:
        if by_verdict.get(v):
            ver_bits.append(_cv("%s=%d" % (v, by_verdict[v]), v, use_color))
    if ver_bits:
        parts.append("Verdict:  " + "  ".join(ver_bits))
    if result.stats.dynamic_hooks:
        parts.append(
            "Note: %d hook(s) with dynamically-built names were skipped."
            % result.stats.dynamic_hooks
        )
    return "\n".join(parts)


def render_findings_detail(result, only_unguarded=False, min_severity=None):
    """Verbose, one-block-per-finding view with reasons and sinks."""
    findings = sorted(_filter(result.findings, only_unguarded, min_severity), key=sort_key)
    blocks = []
    for f in findings:
        b = []
        b.append("[%s] %s  (%s, %s)" % (f.severity, f.target, f.reach, f.verdict))
        b.append("  hook:     %s" % f.hook)
        b.append("  handler:  %s%s" % (f.handler, "" if f.resolved else "  (unresolved)"))
        b.append("  location: %s:%d" % (f.file, f.line))
        b.append("  guards:   %s" % (", ".join(f.guards) if f.guards else "none found"))
        b.append("  sinks:    %s%s" % (
            ", ".join(f.sinks) if f.sinks else "none detected",
            "" if f.sink_level == "none" else "  [%s]" % f.sink_level,
        ))
        for r in f.reasons:
            b.append("  - " + r)
        blocks.append("\n".join(b))
    return "\n\n".join(blocks)


def render_json(result, only_unguarded=False, min_severity=None):
    filtered = sorted(_filter(result.findings, only_unguarded, min_severity), key=sort_key)
    by_sev = {s: 0 for s in SEVERITIES}
    by_verdict = {v: 0 for v in VERDICTS}
    for f in filtered:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_verdict[f.verdict] = by_verdict.get(f.verdict, 0) + 1
    d = result.to_dict()
    d["summary"] = {"total": len(filtered), "by_severity": by_sev, "by_verdict": by_verdict}
    d["findings"] = [f.to_dict() for f in filtered]
    return json.dumps(d, indent=2)


def _filter(findings, only_unguarded, min_severity):
    out = findings
    if only_unguarded:
        out = [f for f in out if f.verdict != "GUARDED"]
    if min_severity:
        thr = SEV_RANK.get(min_severity.upper(), len(SEVERITIES))
        out = [f for f in out if SEV_RANK.get(f.severity, 99) <= thr]
    return out


# --------------------------------------------------------------------------
# Version / fork differential
# --------------------------------------------------------------------------

def _key(f):
    return (f.kind, f.hook, f.target)


def _sig(f):
    return (f.verdict, f.severity, f.sink_level, tuple(sorted(f.guards)))


def diff_results(old, new):
    """Compare two ScanResults. Returns dict with added/removed/changed lists."""
    old_map = {_key(f): f for f in old.findings}
    new_map = {_key(f): f for f in new.findings}
    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    changed = []
    for k in new_map:
        if k in old_map and _sig(new_map[k]) != _sig(old_map[k]):
            changed.append((old_map[k], new_map[k]))
    added.sort(key=sort_key)
    removed.sort(key=sort_key)
    changed.sort(key=lambda pair: sort_key(pair[1]))
    return {"added": added, "removed": removed, "changed": changed}


def render_diff(old, new, use_color=False, only_unguarded=False):
    d = diff_results(old, new)
    added = d["added"]
    removed = d["removed"]
    changed = d["changed"]
    if only_unguarded:
        added = [f for f in added if f.verdict != "GUARDED"]
        changed = [(a, b) for (a, b) in changed if b.verdict != "GUARDED"]

    lines = []
    lines.append(_c("=== Entry-point differential ===", "bold", use_color))
    lines.append("")

    lines.append(_c("+ ADDED (%d)" % len(added), "bold", use_color))
    if not added:
        lines.append("  (none)")
    for f in added:
        lines.append("  " + _c("+", "HIGH", use_color) + " [%s] %s  %s  <%s>  %s" % (
            f.severity, _cv(f.verdict, f.verdict, use_color), f.target, f.reach,
            _rel(f.file, new.root) + ":" + str(f.line)))
    lines.append("")

    lines.append(_c("~ CHANGED (%d)" % len(changed), "bold", use_color))
    if not changed:
        lines.append("  (none)")
    for a, b in changed:
        lines.append("  ~ %s" % b.target)
        lines.append("      verdict:  %s -> %s" % (a.verdict, b.verdict))
        if a.severity != b.severity:
            lines.append("      severity: %s -> %s" % (a.severity, b.severity))
        if sorted(a.guards) != sorted(b.guards):
            lines.append("      guards:   %s -> %s" % (
                ", ".join(a.guards) or "none", ", ".join(b.guards) or "none"))
        if a.sink_level != b.sink_level:
            lines.append("      sinks:    %s -> %s" % (a.sink_level, b.sink_level))
    lines.append("")

    lines.append(_c("- REMOVED (%d)" % len(removed), "bold", use_color))
    if not removed:
        lines.append("  (none)")
    for f in removed:
        lines.append("  - [%s] %s  <%s>" % (f.severity, f.target, f.reach))

    # Highlight the researcher-relevant signal.
    new_bad = [f for f in added if f.verdict in ("UNGUARDED", "WEAK", "UNKNOWN")]
    regressed = [b for (a, b) in changed
                 if a.verdict == "GUARDED" and b.verdict != "GUARDED"]
    lines.append("")
    lines.append(_c("Focus:", "bold", use_color) + " %d newly-exposed and %d regressed entry point(s)."
                 % (len(new_bad), len(regressed)))
    return "\n".join(lines)


def diff_to_json(old, new):
    d = diff_results(old, new)
    return json.dumps(
        {
            "added": [f.to_dict() for f in d["added"]],
            "removed": [f.to_dict() for f in d["removed"]],
            "changed": [{"before": a.to_dict(), "after": b.to_dict()} for a, b in d["changed"]],
        },
        indent=2,
    )
