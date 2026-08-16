"""Command-line interface for wp-hook-guard."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze
from .model import SEV_RANK, SEVERITIES
from . import report


def _want_color(choice):
    if choice == "always":
        return True
    if choice == "never":
        return False
    return sys.stdout.isatty()


def _max_severity_rank(findings):
    if not findings:
        return len(SEVERITIES)  # nothing -> least severe
    return min(SEV_RANK.get(f.severity, len(SEVERITIES)) for f in findings)


def _apply_fail_on(findings, fail_on):
    if not fail_on:
        return 0
    threshold = SEV_RANK.get(fail_on.upper())
    if threshold is None:
        return 0
    worst = _max_severity_rank(findings)
    return 1 if worst <= threshold else 0


def _add_common(p):
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--only-unguarded", action="store_true",
                   help="hide entry points that look correctly guarded")
    p.add_argument("--min-severity", metavar="LEVEL",
                   choices=[s.lower() for s in SEVERITIES],
                   help="only show findings at or above this severity")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="colorize output (default: auto)")
    p.add_argument("--fail-on", metavar="LEVEL",
                   choices=[s.lower() for s in SEVERITIES],
                   help="exit non-zero if any finding is at or above this severity (for CI)")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wp-hook-guard",
        description="Static analyzer that flags WordPress plugin/theme entry "
                    "points missing authorization or nonce guards.",
    )
    parser.add_argument("--version", action="version", version="wp-hook-guard " + __version__)
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a plugin/theme directory or file")
    p_scan.add_argument("path", nargs="+", help="directory or .php file(s) to scan")
    p_scan.add_argument("--detail", action="store_true",
                        help="verbose, one block per finding (reasons + sinks)")
    _add_common(p_scan)

    p_diff = sub.add_parser(
        "diff", help="compare two versions and highlight new/regressed entry points")
    p_diff.add_argument("old", help="path to the OLD version")
    p_diff.add_argument("new", help="path to the NEW version")
    _add_common(p_diff)

    return parser


def _cmd_scan(args):
    result = analyze(list(args.path))
    use_color = _want_color(args.color)
    if args.json:
        print(report.render_json(result, args.only_unguarded, args.min_severity))
    elif getattr(args, "detail", False):
        detail = report.render_findings_detail(result, args.only_unguarded, args.min_severity)
        if detail:
            print(detail)
            print()
        print(report.render_summary(result, use_color))
    else:
        print(report.render_table(result, use_color, args.only_unguarded, args.min_severity))
    shown = report._filter(result.findings, args.only_unguarded, args.min_severity)
    return _apply_fail_on(shown, args.fail_on)


def _cmd_diff(args):
    old = analyze([args.old])
    new = analyze([args.new])
    use_color = _want_color(args.color)
    if args.json:
        print(report.diff_to_json(old, new))
    else:
        print(report.render_diff(old, new, use_color, args.only_unguarded))
    d = report.diff_results(old, new)
    changed_after = [b for _, b in d["changed"]]
    return _apply_fail_on(d["added"] + changed_after, args.fail_on)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "diff":
        return _cmd_diff(args)
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
