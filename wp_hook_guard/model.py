"""Public data structures returned by the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field


# Severity ordering (lower index == more severe).
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Verdicts:
#   UNGUARDED  reachable + sensitive operation + no appropriate authz guard
#   WEAK       a guard exists but a real gap remains (e.g. missing CSRF nonce,
#              or the endpoint is public with no obvious sink to confirm impact)
#   UNKNOWN    handler / permission could not be resolved statically
#   GUARDED    an appropriate authorization guard was found
VERDICTS = ["UNGUARDED", "WEAK", "UNKNOWN", "GUARDED"]


@dataclass
class Finding:
    kind: str            # 'ajax' | 'admin_post' | 'rest' | 'init'
    reach: str           # 'unauthenticated' | 'authenticated' | 'unknown'
    hook: str            # e.g. 'wp_ajax_nopriv_foo', 'admin_init', 'rest'
    action: str          # action slug, or REST route, or handler name for init
    target: str          # human display for the ACTION/ROUTE column
    handler: str         # resolved handler display name
    resolved: bool       # was the handler/permission resolvable statically?
    guards: list         # e.g. ['cap:manage_options', 'nonce:check_ajax_referer']
    sinks: list          # detected sensitive operations
    sink_level: str      # 'dangerous' | 'write' | 'read' | 'none'
    verdict: str         # see VERDICTS
    severity: str        # see SEVERITIES
    reasons: list         # human-readable justification lines
    file: str            # absolute path
    line: int

    def to_dict(self):
        return {
            "kind": self.kind,
            "reach": self.reach,
            "hook": self.hook,
            "action": self.action,
            "target": self.target,
            "handler": self.handler,
            "resolved": self.resolved,
            "guards": list(self.guards),
            "sinks": list(self.sinks),
            "sink_level": self.sink_level,
            "verdict": self.verdict,
            "severity": self.severity,
            "reasons": list(self.reasons),
            "file": self.file,
            "line": self.line,
        }


@dataclass
class Stats:
    files_scanned: int = 0
    dynamic_hooks: int = 0   # hooks whose name was computed at runtime (skipped)

    def to_dict(self):
        return {"files_scanned": self.files_scanned, "dynamic_hooks": self.dynamic_hooks}


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    stats: Stats = field(default_factory=Stats)
    root: str = ""

    def counts(self):
        """Return (by_severity, by_verdict) dicts."""
        by_sev = {s: 0 for s in SEVERITIES}
        by_verdict = {v: 0 for v in VERDICTS}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_verdict[f.verdict] = by_verdict.get(f.verdict, 0) + 1
        return by_sev, by_verdict

    def to_dict(self):
        by_sev, by_verdict = self.counts()
        return {
            "root": self.root,
            "stats": self.stats.to_dict(),
            "summary": {
                "total": len(self.findings),
                "by_severity": by_sev,
                "by_verdict": by_verdict,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
