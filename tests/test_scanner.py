"""Unit tests for wp-hook-guard (stdlib unittest only)."""

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from wp_hook_guard.analyzer import analyze, assess
from wp_hook_guard import report
from wp_hook_guard.cli import main

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fx(*parts):
    return os.path.join(FIX, *parts)


def by_action(findings):
    """Index findings by action; hook-qualified for uniqueness where needed."""
    out = {}
    for f in findings:
        out.setdefault(f.action, []).append(f)
    return out


def find_one(findings, **match):
    """Return the single finding matching all attr==value (substring for target)."""
    hits = []
    for f in findings:
        ok = True
        for k, v in match.items():
            cur = getattr(f, k)
            if k == "target":
                ok = ok and (v in cur)
            else:
                ok = ok and (cur == v)
        if ok:
            hits.append(f)
    if len(hits) != 1:
        raise AssertionError("expected exactly 1 finding for %r, got %d" % (match, len(hits)))
    return hits[0]


class VulnerableFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("vulnerable-plugin")]).findings

    def test_nopriv_ajax_option_write_is_critical(self):
        f = find_one(self.findings, hook="wp_ajax_nopriv_vg_save_settings")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("update_option", f.sinks)
        self.assertEqual(f.guards, [])

    def test_same_handler_authenticated_registration_is_high(self):
        f = find_one(self.findings, hook="wp_ajax_vg_save_settings")
        self.assertEqual(f.reach, "authenticated")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertEqual(f.severity, "HIGH")

    def test_admin_post_nopriv_delete_is_unguarded(self):
        f = find_one(self.findings, hook="admin_post_nopriv_vg_delete")
        self.assertEqual(f.kind, "admin_post")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertTrue(any("$wpdb->query" in s for s in f.sinks))

    def test_init_handler_reading_superglobal_is_flagged(self):
        f = find_one(self.findings, kind="init", action="vg_maybe_export")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.severity, "MEDIUM")   # read-only info disclosure
        self.assertIn("get_option", f.sinks)

    def test_rest_return_true_is_critical_public(self):
        f = find_one(self.findings, kind="rest", target="/vg/v1/wipe")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("permission:__return_true", f.guards)
        self.assertIn("delete_option", f.sinks)

    def test_everything_is_unguarded_here(self):
        self.assertTrue(all(f.verdict == "UNGUARDED" for f in self.findings))
        self.assertEqual(len(self.findings), 5)


class SafeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("safe-plugin")]).findings

    def test_nothing_is_unguarded(self):
        bad = [f for f in self.findings if f.verdict != "GUARDED"]
        self.assertEqual(bad, [], "expected all guarded, got: %r" % [(f.target, f.verdict) for f in bad])

    def test_ajax_guards_are_detected(self):
        f = find_one(self.findings, hook="wp_ajax_sg_save_settings")
        self.assertEqual(f.verdict, "GUARDED")
        self.assertIn("cap:manage_options", f.guards)
        self.assertIn("nonce:check_ajax_referer", f.guards)

    def test_rest_closure_permission_is_guarded(self):
        f = find_one(self.findings, kind="rest", target="/sg/v1/settings")
        self.assertEqual(f.verdict, "GUARDED")
        self.assertIn("cap:manage_options", f.guards)


class ClassResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("class-plugin")]).findings

    def test_this_method_is_resolved(self):
        f = find_one(self.findings, action="vgc_ping")
        self.assertTrue(f.resolved)
        self.assertEqual(f.handler, "VG_Class_Plugin::ping")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertEqual(f.severity, "HIGH")

    def test_guarded_method_detected(self):
        f = find_one(self.findings, action="vgc_secure")
        self.assertEqual(f.verdict, "GUARDED")
        self.assertIn("cap:manage_options", f.guards)

    def test_dynamic_callback_is_unknown(self):
        f = find_one(self.findings, action="vgc_dyn")
        self.assertFalse(f.resolved)
        self.assertEqual(f.verdict, "UNKNOWN")


class LexerRobustnessTests(unittest.TestCase):
    """Hook-like text in comments/strings must never become a finding."""

    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("tricky")]).findings

    def test_only_real_hook_is_found(self):
        actions = {f.action for f in self.findings}
        self.assertIn("real_one", actions)
        for ghost in ("commented_out", "in_string", "block_comment", "hash_comment"):
            self.assertNotIn(ghost, actions)

    def test_exactly_one_finding(self):
        self.assertEqual(len(self.findings), 1)


class InitGatingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("init-cases")]).findings

    def test_benign_reader_is_not_reported(self):
        self.assertNotIn("ic_benign", {f.action for f in self.findings})

    def test_sensitive_init_reader_is_reported(self):
        f = find_one(self.findings, action="ic_apply")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.verdict, "UNGUARDED")

    def test_admin_init_is_authenticated(self):
        f = find_one(self.findings, action="ic_admin_apply")
        self.assertEqual(f.reach, "authenticated")


class RestEdgeCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = analyze([fx("rest-cases")]).findings

    def test_missing_permission_key_is_public(self):
        f = find_one(self.findings, target="/rc/v1/open")
        self.assertEqual(f.reach, "unauthenticated")
        self.assertEqual(f.verdict, "UNGUARDED")
        self.assertIn("permission:missing", f.guards)

    def test_named_permission_function_is_resolved(self):
        f = find_one(self.findings, target="/rc/v1/closed")
        self.assertEqual(f.verdict, "GUARDED")
        self.assertIn("cap:manage_options", f.guards)


class ScoringUnitTests(unittest.TestCase):
    def test_unauth_dangerous_unguarded_is_critical(self):
        v, s, _ = assess("unauthenticated", False, False, False, "dangerous", "ajax", True)
        self.assertEqual((v, s), ("UNGUARDED", "CRITICAL"))

    def test_authenticated_write_no_cap_is_medium(self):
        v, s, _ = assess("authenticated", False, False, False, "write", "ajax", True)
        self.assertEqual((v, s), ("UNGUARDED", "MEDIUM"))

    def test_cap_but_no_nonce_on_write_is_weak_csrf(self):
        v, s, _ = assess("authenticated", True, False, False, "write", "admin_post", True)
        self.assertEqual(v, "WEAK")

    def test_cap_and_nonce_is_guarded(self):
        v, s, _ = assess("authenticated", True, False, True, "dangerous", "ajax", True)
        self.assertEqual((v, s), ("GUARDED", "INFO"))

    def test_is_user_logged_in_downgrades_unauth_to_authenticated(self):
        # nopriv handler that at least checks login: dangerous op -> HIGH, not CRITICAL
        v, s, _ = assess("unauthenticated", False, True, False, "dangerous", "ajax", True)
        self.assertEqual(s, "HIGH")

    def test_unresolved_is_unknown(self):
        v, s, _ = assess("unauthenticated", False, False, False, "none", "ajax", False)
        self.assertEqual(v, "UNKNOWN")


class DiffTests(unittest.TestCase):
    def test_added_and_removed(self):
        old = analyze([fx("safe-plugin")])
        new = analyze([fx("vulnerable-plugin")])
        d = report.diff_results(old, new)
        self.assertTrue(len(d["added"]) >= 5)
        self.assertTrue(all(f.verdict == "UNGUARDED" for f in d["added"]))
        self.assertTrue(len(d["removed"]) >= 3)

    def test_diff_json_parses(self):
        old = analyze([fx("safe-plugin")])
        new = analyze([fx("vulnerable-plugin")])
        parsed = json.loads(report.diff_to_json(old, new))
        self.assertIn("added", parsed)
        self.assertIn("removed", parsed)


class OutputTests(unittest.TestCase):
    def test_json_is_valid_and_summarized(self):
        result = analyze([fx("vulnerable-plugin")])
        parsed = json.loads(report.render_json(result))
        self.assertEqual(parsed["summary"]["total"], 5)
        self.assertEqual(parsed["summary"]["by_verdict"]["UNGUARDED"], 5)

    def test_only_unguarded_filter_hides_guarded(self):
        result = analyze([fx("safe-plugin")])
        parsed = json.loads(report.render_json(result, only_unguarded=True))
        self.assertEqual(parsed["summary"]["total"], 0)

    def test_table_renders_without_error(self):
        result = analyze([fx("vulnerable-plugin")])
        text = report.render_table(result, use_color=False)
        self.assertIn("UNGUARDED", text)
        self.assertIn("vg_save_settings", text)


class CliTests(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_fail_on_high_trips_on_vulnerable(self):
        code, _ = self._run(["scan", fx("vulnerable-plugin"), "--fail-on", "high", "--color", "never"])
        self.assertEqual(code, 1)

    def test_fail_on_high_passes_on_safe(self):
        code, _ = self._run(["scan", fx("safe-plugin"), "--fail-on", "high", "--color", "never"])
        self.assertEqual(code, 0)

    def test_scan_default_exit_zero(self):
        code, out = self._run(["scan", fx("vulnerable-plugin"), "--color", "never"])
        self.assertEqual(code, 0)
        self.assertIn("Severity:", out)

    def test_diff_subcommand_runs(self):
        code, out = self._run(["diff", fx("safe-plugin"), fx("vulnerable-plugin"), "--color", "never"])
        self.assertIn("ADDED", out)


if __name__ == "__main__":
    unittest.main()
