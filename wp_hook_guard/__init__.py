"""wp-hook-guard: static access-control triage for WordPress plugins & themes.

Public API::

    from wp_hook_guard import scan_path, analyze
    result = scan_path("/path/to/plugin")
    for f in result.findings:
        print(f.severity, f.target, f.verdict)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .analyzer import analyze, scan_path  # noqa: E402
from .model import Finding, ScanResult, Stats  # noqa: E402

__all__ = ["analyze", "scan_path", "Finding", "ScanResult", "Stats", "__version__"]
