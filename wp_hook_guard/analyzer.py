"""The static analysis engine.

Pipeline:
  1. Lex every .php file into significant tokens (see :mod:`tokenizer`).
  2. Index all function / method / class definitions across the whole tree so
     handlers can be resolved even when defined in another file.
  3. Walk each file for entry-point registrations:
       add_action('wp_ajax_*' / 'wp_ajax_nopriv_*' / 'admin_post_*' / ...)
       add_action('init' | 'admin_init' | 'wp_loaded', ...)
       register_rest_route(..., array('permission_callback' => ...))
  4. Resolve each handler to a body, scan the body for authorization guards and
     for sensitive "sink" operations, and score reachability vs. guarding.

Everything is best-effort and heuristic; see README "Limitations".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .model import Finding, ScanResult, Stats
from .tokenizer import (
    tokenize,
    significant,
    match_paren,
    match_brace,
    match_group,
    split_top_commas,
)

# --------------------------------------------------------------------------
# Vocabulary: what counts as a guard, and what counts as a sensitive sink.
# --------------------------------------------------------------------------

CAP_FUNCS = {"current_user_can", "current_user_can_for_blog", "author_can", "user_can"}
NONCE_FUNCS = {"check_ajax_referer", "check_admin_referer", "wp_verify_nonce"}
AUTH_FUNCS = {"is_user_logged_in"}

SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_FILES", "$_COOKIE"}

# Sink level ordering.
_LEVEL_RANK = {"none": 0, "read": 1, "write": 2, "dangerous": 3}


def _worse(a, b):
    return a if _LEVEL_RANK[a] >= _LEVEL_RANK[b] else b


# Function-name -> sink level.  "dangerous" = RCE / arbitrary file / option /
# account / deserialization; "write" = other state changes & outbound requests;
# "read" = potentially sensitive reads (info disclosure).
SINK_LEVELS = {}


def _reg(level, *names):
    for n in names:
        SINK_LEVELS[n] = level


_reg(
    "dangerous",
    "eval", "assert", "create_function", "system", "exec", "shell_exec",
    "passthru", "popen", "proc_open", "pcntl_exec", "unserialize", "extract",
    "call_user_func", "call_user_func_array",
    "file_put_contents", "fwrite", "fputs", "unlink", "rename", "copy",
    "move_uploaded_file", "mkdir", "rmdir", "chmod", "chown", "symlink", "link",
    "wp_insert_user", "wp_create_user", "wp_update_user", "wp_set_password",
    "wp_delete_user", "add_user_to_blog",
    "update_option", "add_option", "delete_option", "update_site_option",
    "add_site_option", "delete_site_option",
    "wp_handle_upload", "wp_handle_sideload", "download_url",
)
_reg(
    "write",
    "wp_insert_post", "wp_update_post", "wp_delete_post", "wp_trash_post",
    "wp_publish_post", "wp_insert_comment", "wp_update_comment",
    "wp_delete_comment", "wp_set_comment_status",
    "update_post_meta", "add_post_meta", "delete_post_meta",
    "update_user_meta", "add_user_meta", "delete_user_meta",
    "update_term_meta", "add_term_meta", "delete_term_meta",
    "wp_set_object_terms", "wp_insert_term", "wp_update_term", "wp_delete_term",
    "wp_set_post_terms", "wp_mail", "wp_redirect", "wp_safe_redirect",
    "wp_remote_get", "wp_remote_post", "wp_remote_request", "curl_exec",
    "fsockopen", "fopen", "fputcsv", "set_transient", "delete_transient",
)
_reg(
    "read",
    "file_get_contents", "readfile", "fread", "fgets", "fgetcsv",
    "get_option", "get_site_option", "get_user_meta", "get_post_meta",
    "get_term_meta", "get_users", "get_userdata", "get_user_by",
    "wp_get_current_user", "glob", "scandir", "opendir", "readdir",
)

INCLUDE_FUNCS = {"include", "include_once", "require", "require_once"}

# WP_REST_Server method-constant -> HTTP verb, for display.
REST_METHOD_CONSTS = {
    "READABLE": "GET",
    "CREATABLE": "POST",
    "EDITABLE": "POST,PUT,PATCH",
    "DELETABLE": "DELETE",
    "ALLMETHODS": "ANY",
}


# --------------------------------------------------------------------------
# Internal structures
# --------------------------------------------------------------------------

class FileUnit:
    __slots__ = ("path", "src", "tokens", "sig", "classes")

    def __init__(self, path, src, tokens, sig):
        self.path = path
        self.src = src
        self.tokens = tokens
        self.sig = sig
        self.classes = []  # list of (name, body_open_idx, body_close_idx)


@dataclass
class Def:
    name: str
    cls: str            # class name or "" for a free function
    owner: FileUnit
    body_open: int      # index of '{'
    body_end: int       # index of matching '}'
    line: int


@dataclass
class Handler:
    display: str
    resolved: bool
    owner: FileUnit = None
    body_lo: int = -1
    body_hi: int = -1
    note: str = ""

    @property
    def has_body(self):
        return self.resolved and self.owner is not None and self.body_lo >= 0


@dataclass
class BodyInfo:
    caps: list = field(default_factory=list)
    nonces: list = field(default_factory=list)
    auth: bool = False
    reads_superglobal: bool = False
    sinks: list = field(default_factory=list)
    level: str = "none"


class Project:
    def __init__(self, units):
        self.units = units
        self.functions = {}       # lname -> [Def, ...]
        self.methods = {}         # (lclass, lmethod) -> Def
        self.methods_by_name = {}  # lmethod -> [Def, ...]
        self._index()

    def _index(self):
        for unit in self.units:
            _index_unit(unit, self)


# --------------------------------------------------------------------------
# Definition indexing
# --------------------------------------------------------------------------

def _enclosing_class(classes, idx):
    """Innermost class whose body contains token index ``idx`` (or "")."""
    best = ""
    best_open = -1
    for name, open_i, close_i in classes:
        if open_i < idx < close_i and open_i > best_open:
            best = name
            best_open = open_i
    return best


def _index_unit(unit, project):
    sig = unit.sig
    n = len(sig)

    # Class / trait / interface spans first.
    i = 0
    while i < n:
        t = sig[i]
        if (
            t.kind == "ident"
            and t.text.lower() in ("class", "trait", "interface")
            and i + 1 < n
            and sig[i + 1].kind == "ident"
        ):
            cname = sig[i + 1].text
            j = i + 2
            while j < n and not (sig[j].kind == "punct" and sig[j].text in ("{", ";")):
                j += 1
            if j < n and sig[j].text == "{":
                end = match_brace(sig, j)
                unit.classes.append((cname, j, end))
                i = j
        i += 1

    # Function / method definitions.
    i = 0
    while i < n:
        t = sig[i]
        if t.kind == "ident" and t.text.lower() == "function":
            k = i + 1
            if k < n and sig[k].text == "&":
                k += 1
            name = None
            if k < n and sig[k].kind == "ident":
                name = sig[k].text
                k += 1
            if k < n and sig[k].text == "(":
                pclose = match_paren(sig, k)
                m = pclose + 1
                body_open = None
                while m < n:
                    tt = sig[m]
                    if tt.kind == "punct" and tt.text == "{":
                        body_open = m
                        break
                    if tt.kind == "punct" and tt.text in (";", "{", "}"):
                        break
                    m += 1
                if body_open is not None:
                    body_end = match_brace(sig, body_open)
                    if name:
                        cls = _enclosing_class(unit.classes, i)
                        d = Def(name, cls, unit, body_open, body_end, t.line)
                        if cls:
                            project.methods[(cls.lower(), name.lower())] = d
                            project.methods_by_name.setdefault(name.lower(), []).append(d)
                        else:
                            project.functions.setdefault(name.lower(), []).append(d)
                    i = body_open
        i += 1


# --------------------------------------------------------------------------
# Call finding
# --------------------------------------------------------------------------

def _find_calls(unit, names):
    """Yield (ident_idx, open_paren_idx, close_paren_idx) for calls to ``names``."""
    sig = unit.sig
    n = len(sig)
    for i in range(n):
        t = sig[i]
        if t.kind != "ident":
            continue
        if t.text.lstrip("\\").lower() not in names:
            continue
        if i + 1 >= n or not (sig[i + 1].kind == "punct" and sig[i + 1].text == "("):
            continue
        if i > 0:
            prev = sig[i - 1]
            if prev.kind == "punct" and prev.text in ("->", "::"):
                continue
            if prev.kind == "ident" and prev.text.lower() == "function":
                continue
        yield i, i + 1, match_paren(sig, i + 1)


def _str_value(sig, idx):
    t = sig[idx]
    return t.value if t.kind == "str" else None


def _first(lst):
    return lst[0] if lst else None


# --------------------------------------------------------------------------
# Handler / callback resolution
# --------------------------------------------------------------------------

def _resolve_callback(project, unit, lo, hi, call_idx):
    """Resolve the second argument of add_action (a PHP "callable") to a Handler."""
    sig = unit.sig
    if lo >= hi:
        return Handler("<empty>", False, note="empty callback")
    first = sig[lo]

    # 'function_name' or 'Class::method'
    if first.kind == "str" and hi - lo == 1:
        val = first.value
        if "::" in val:
            cls, meth = val.split("::", 1)
            d = project.methods.get((cls.strip("\\").lower(), meth.lower())) \
                or _first(project.methods_by_name.get(meth.lower()))
            return _handler_from_def(d, val)
        d = _first(project.functions.get(val.lower()))
        return _handler_from_def(d, val)

    # Array callable: [ $this, 'm' ] / array($this,'m') / ['Class','m'] / [Class::class,'m']
    is_bracket = first.kind == "punct" and first.text == "["
    is_array_kw = (
        first.kind == "ident"
        and first.text.lower() == "array"
        and lo + 1 < hi
        and sig[lo + 1].text == "("
    )
    if is_bracket or is_array_kw:
        if is_bracket:
            inner_lo = lo + 1
            inner_hi = match_group(sig, lo, "[", "]")
        else:
            popen = lo + 1
            inner_hi = match_paren(sig, popen)
            inner_lo = popen + 1
        parts = split_top_commas(sig, inner_lo, inner_hi)
        if len(parts) >= 2:
            e0 = parts[0]
            e1 = parts[1]
            mtok = sig[e1[0]]
            if mtok.kind == "str":
                meth = mtok.value
                clsname = _class_of_element(sig, e0, unit, call_idx)
                if clsname:
                    d = project.methods.get((clsname.strip("\\").lower(), meth.lower())) \
                        or _first(project.methods_by_name.get(meth.lower()))
                    display = clsname.strip("\\") + "::" + meth
                else:
                    d = _first(project.methods_by_name.get(meth.lower()))
                    display = "?::" + meth
                return _handler_from_def(d, display)
        return Handler("<array-callable>", False, note="unresolved array callable")

    # Closures / arrow functions.
    p = lo
    if sig[p].kind == "ident" and sig[p].text.lower() == "static":
        p += 1
    if p < hi and sig[p].kind == "ident" and sig[p].text.lower() == "fn":
        a = p
        while a < hi and not (sig[a].kind == "punct" and sig[a].text == "=>"):
            a += 1
        return Handler("fn(){closure}", True, unit, a + 1, hi)
    if p < hi and sig[p].kind == "ident" and sig[p].text.lower() == "function":
        b = p
        while b < hi and not (sig[b].kind == "punct" and sig[b].text == "{"):
            b += 1
        if b < hi:
            e = match_brace(sig, b)
            return Handler("function(){closure}", True, unit, b + 1, e)
        return Handler("function(){...}", False, note="unparsable closure")

    # Anything else: $var, $this->prop, dynamic string, etc.
    return Handler("<dynamic>", False, note="dynamic/indirect callable")


def _class_of_element(sig, rng, unit, call_idx):
    lo, hi = rng
    tok = sig[lo]
    if tok.kind == "var" and tok.text == "$this":
        return _enclosing_class(unit.classes, call_idx)
    if tok.kind == "str":
        return tok.value.split("::")[0]
    if tok.kind == "ident":
        # Class::class or bare Class name
        return tok.text
    return None


def _handler_from_def(d, display):
    if d is None:
        return Handler(display, False, note="handler not found in scanned source")
    return Handler(display, True, d.owner, d.body_open + 1, d.body_end)


# --------------------------------------------------------------------------
# Body scanning: guards + sinks
# --------------------------------------------------------------------------

def _first_str_arg(sig, paren_idx, hi):
    if paren_idx + 1 < hi and sig[paren_idx + 1].kind == "str":
        return sig[paren_idx + 1].value
    return None


def _scan_body(sig, lo, hi):
    info = BodyInfo()
    j = lo
    while j < hi:
        t = sig[j]
        if t.kind == "var":
            if t.text in SUPERGLOBALS:
                info.reads_superglobal = True
            elif t.text == "$wpdb" and j + 2 < hi and sig[j + 1].text == "->" \
                    and sig[j + 2].kind == "ident":
                m = sig[j + 2].text.lower()
                if m in ("query", "insert", "update", "delete", "replace", "get_results", "get_row", "get_col", "get_var"):
                    info.sinks.append("$wpdb->" + m)
                    info.level = _worse(info.level, "read" if m.startswith("get_") else "write")
        elif t.kind == "ident":
            name = t.text.lstrip("\\").lower()
            is_call = j + 1 < hi and sig[j + 1].kind == "punct" and sig[j + 1].text == "("
            if name in INCLUDE_FUNCS:
                info.sinks.append(name)
                info.level = _worse(info.level, "dangerous")
            elif is_call and name in CAP_FUNCS:
                cap = _first_str_arg(sig, j + 1, hi)
                info.caps.append(cap or name)
            elif is_call and name in NONCE_FUNCS:
                info.nonces.append(name)
            elif is_call and name in AUTH_FUNCS:
                info.auth = True
            elif is_call and name in SINK_LEVELS:
                info.sinks.append(name)
                info.level = _worse(info.level, SINK_LEVELS[name])
        j += 1
    return info


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

_BASE_SEVERITY = {
    ("unauthenticated", "dangerous"): "CRITICAL",
    ("unauthenticated", "write"): "HIGH",
    ("unauthenticated", "read"): "MEDIUM",
    ("unauthenticated", "none"): "LOW",
    ("authenticated", "dangerous"): "HIGH",
    ("authenticated", "write"): "MEDIUM",
    ("authenticated", "read"): "LOW",
    ("authenticated", "none"): "LOW",
}


def _base_severity(reach, level):
    return _BASE_SEVERITY[(reach, level)]


def assess(reach, has_cap, has_auth, has_nonce, level, kind, resolved):
    """Return (verdict, severity, reasons)."""
    if not resolved:
        return (
            "UNKNOWN",
            "MEDIUM" if reach == "unauthenticated" else "LOW",
            ["handler could not be resolved statically (dynamic or indirect); review manually"],
        )

    reasons = []
    eff = reach
    if reach == "unauthenticated" and has_auth and not has_cap:
        eff = "authenticated"
        reasons.append("is_user_logged_in() limits access to logged-in users but not by capability")

    sensitive = level != "none"

    if not has_cap:
        if eff == "unauthenticated":
            reasons.insert(0, "reachable by unauthenticated users with no capability or authentication check")
        else:
            reasons.insert(0, "reachable by any authenticated user (e.g. Subscriber) with no capability check")
        sev = _base_severity(eff, level)
        if sensitive:
            return "UNGUARDED", sev, reasons
        reasons.append("no sensitive sink detected in handler body (could be benign, or use indirection)")
        return "WEAK", sev, reasons

    # Capability check present.
    if level in ("dangerous", "write") and not has_nonce and kind in ("ajax", "admin_post", "init"):
        return (
            "WEAK",
            "MEDIUM" if level == "dangerous" else "LOW",
            ["capability check present, but no CSRF nonce check on a state-changing handler (possible CSRF)"],
        )
    reasons.insert(0, "capability check present")
    return "GUARDED", "INFO", reasons


def _guards_list(info):
    guards = []
    for c in info.caps:
        guards.append("cap:" + c)
    for nfn in info.nonces:
        guards.append("nonce:" + nfn)
    if info.auth:
        guards.append("auth:is_user_logged_in")
    return guards


# --------------------------------------------------------------------------
# Hook classification
# --------------------------------------------------------------------------

_ACTION_PREFIXES = [
    ("wp_ajax_nopriv_", "ajax", "unauthenticated"),
    ("wp_ajax_", "ajax", "authenticated"),
    ("admin_post_nopriv_", "admin_post", "unauthenticated"),
    ("admin_post_", "admin_post", "authenticated"),
]
_INIT_HOOKS = {"init": "unauthenticated", "wp_loaded": "unauthenticated", "admin_init": "authenticated"}


def _classify_hook_name(h, dynamic):
    for prefix, kind, reach in _ACTION_PREFIXES:
        if h.startswith(prefix):
            action = h[len(prefix):]
            if not action:
                if not dynamic:
                    return None  # bare generic hook, not an entry point
                action = "<dynamic>"
            hook = h if not dynamic else prefix + "<dynamic>"
            return {"kind": kind, "reach": reach, "action": action, "hook": hook, "dynamic": dynamic}
    if not dynamic and h in _INIT_HOOKS:
        return {"kind": "init", "reach": _INIT_HOOKS[h], "action": "", "hook": h, "dynamic": False}
    return None


def _classify_hook(sig, name_range):
    lo, hi = name_range
    if hi - lo == 1 and sig[lo].kind == "str":
        return _classify_hook_name(sig[lo].value, dynamic=False)
    # Concatenation that *starts* with a known-prefix literal: "wp_ajax_" . $x
    if sig[lo].kind == "str":
        return _classify_hook_name(sig[lo].value, dynamic=True)
    return None


# --------------------------------------------------------------------------
# Finding construction: action hooks
# --------------------------------------------------------------------------

def _make_hook_finding(unit, hk, handler, stats):
    kind = hk["kind"]
    reach = hk["reach"]
    info = _scan_body(handler.owner.sig, handler.body_lo, handler.body_hi) if handler.has_body else BodyInfo()

    if kind == "init":
        # High-signal only: an init/admin_init/wp_loaded handler is interesting
        # when it both reads user input and performs a sensitive operation.
        if not (info.reads_superglobal and info.level != "none"):
            return None

    verdict, severity, reasons = assess(
        reach,
        has_cap=bool(info.caps),
        has_auth=info.auth,
        has_nonce=bool(info.nonces),
        level=info.level,
        kind=kind,
        resolved=handler.resolved,
    )

    if kind == "init":
        action = handler.display
        target = handler.display + "  (via " + hk["hook"] + ")"
        reasons.append("handler reads a superglobal on every " + hk["hook"] + " request")
    else:
        action = hk["action"]
        target = action
    if hk.get("dynamic"):
        reasons.append("hook name is built dynamically; action shown as <dynamic>")

    return Finding(
        kind=kind,
        reach=reach,
        hook=hk["hook"],
        action=action,
        target=target,
        handler=handler.display,
        resolved=handler.resolved,
        guards=_guards_list(info),
        sinks=list(info.sinks),
        sink_level=info.level,
        verdict=verdict,
        severity=severity,
        reasons=reasons,
        file=unit.path,
        line=hk["_line"],
    )


# --------------------------------------------------------------------------
# Finding construction: REST routes
# --------------------------------------------------------------------------

def _capture_value_after(sig, arrow_idx, hi):
    start = arrow_idx + 1
    depth = 0
    i = start
    while i < hi:
        t = sig[i]
        if t.kind == "punct":
            if t.text in ("(", "[", "{"):
                depth += 1
            elif t.text in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif t.text == "," and depth == 0:
                break
        i += 1
    return start, i


def _route_path(namespace, route):
    ns = (namespace or "").strip("/")
    rt = (route or "").strip("/")
    if ns and rt:
        return "/" + ns + "/" + rt
    if ns:
        return "/" + ns
    return "/" + rt


def _methods_display(sig, rng):
    lo, hi = rng
    if hi - lo == 1 and sig[lo].kind == "str":
        return sig[lo].value
    parts = []
    for j in range(lo, hi):
        t = sig[j]
        if t.kind == "ident":
            seg = t.text.split("::")[-1].split("\\")[-1]
            parts.append(REST_METHOD_CONSTS.get(seg.upper(), t.text))
        elif t.kind == "str":
            parts.append(t.value)
    return ",".join(p for p in parts if p) or "?"


def _find_keys(sig, lo, hi, wanted):
    """Return {key: [value_range, ...]} for assoc-array keys inside [lo, hi)."""
    out = {}
    for j in range(lo, hi):
        t = sig[j]
        if t.kind == "str" and t.value in wanted and j + 1 < hi \
                and sig[j + 1].kind == "punct" and sig[j + 1].text == "=>":
            vr = _capture_value_after(sig, j + 1, hi)
            out.setdefault(t.value, []).append(vr)
    return out


def _evaluate_permission(project, unit, vr):
    """Return (state, note, guards) where state in {'public','closed','guarded','unknown'}."""
    lo, hi = vr
    if lo >= hi:
        return "public", "permission_callback is empty", ["permission:none"]
    sig = unit.sig
    first = sig[lo]
    literal = None
    if first.kind == "ident" and hi - lo == 1:
        literal = first.text.lstrip("\\").lower()
    elif first.kind == "str" and hi - lo == 1:
        literal = first.value.lower()
    if literal == "__return_true":
        return "public", "permission_callback => __return_true (route is public)", ["permission:__return_true"]
    if literal == "__return_false":
        return "closed", "permission_callback => __return_false (route denies all)", ["permission:__return_false"]

    handler = _resolve_callback(project, unit, lo, hi, lo)
    if not handler.has_body:
        return "unknown", "permission_callback could not be resolved statically", ["permission:" + handler.display]
    info = _scan_body(handler.owner.sig, handler.body_lo, handler.body_hi)
    if info.caps or info.auth:
        g = _guards_list(info) or ["permission:check"]
        return "guarded", "permission_callback performs a capability/auth check", g
    return "public", "permission_callback does not check capability or login (effectively public)", ["permission:" + handler.display]


def _make_rest_findings(project, unit, call_idx, popen, pclose):
    sig = unit.sig
    line = sig[call_idx].line
    args = split_top_commas(sig, popen + 1, pclose)
    namespace = _str_value(sig, args[0][0]) if len(args) >= 1 else None
    route = _str_value(sig, args[1][0]) if len(args) >= 2 else None
    route_path = _route_path(namespace, route)

    findings = []

    if len(args) < 3:
        # No options array at all -> defaults to publicly reachable.
        findings.append(_rest_finding(unit, line, route_path, "?", "public",
                                       "no options array passed; route has no permission_callback",
                                       ["permission:missing"], Handler("<none>", False), project))
        return findings

    a2lo, a2hi = args[2]
    keys = _find_keys(sig, a2lo, a2hi, {"permission_callback", "callback", "methods"})
    methods_disp = _methods_display(sig, keys["methods"][0]) if "methods" in keys else "?"

    # Resolve the primary callback (for sink/impact estimation).
    if "callback" in keys:
        clo, chi = keys["callback"][0]
        cb_handler = _resolve_callback(project, unit, clo, chi, call_idx)
    else:
        cb_handler = Handler("<none>", False, note="no callback key")

    is_array_literal = sig[a2lo].text == "[" or (
        sig[a2lo].kind == "ident" and sig[a2lo].text.lower() == "array"
    )

    if "permission_callback" not in keys:
        if not is_array_literal:
            findings.append(_rest_finding(unit, line, route_path, methods_disp, "unknown",
                                          "options argument is not a literal array; cannot verify permission_callback",
                                          ["permission:unknown"], cb_handler, project))
        else:
            findings.append(_rest_finding(unit, line, route_path, methods_disp, "public",
                                          "no permission_callback key (defaults to publicly reachable; WP warns since 5.5)",
                                          ["permission:missing"], cb_handler, project))
        return findings

    for vr in keys["permission_callback"]:
        state, note, guards = _evaluate_permission(project, unit, vr)
        findings.append(_rest_finding(unit, line, route_path, methods_disp, state, note, guards, cb_handler, project))
    return findings


def _rest_finding(unit, line, route_path, methods_disp, state, note, guards, cb_handler, project):
    info = _scan_body(cb_handler.owner.sig, cb_handler.body_lo, cb_handler.body_hi) if cb_handler.has_body else BodyInfo()
    level = info.level
    sinks = list(info.sinks)
    reasons = [note]

    if state == "unknown":
        verdict, severity = "UNKNOWN", "MEDIUM"
    elif state in ("guarded", "closed"):
        verdict, severity = "GUARDED", "INFO"
    else:  # public
        verdict = "UNGUARDED"
        severity = _base_severity("unauthenticated", level)
        reasons.append("REST route is reachable without authentication")

    reach = "authenticated" if state in ("guarded", "closed") else \
            ("unknown" if state == "unknown" else "unauthenticated")

    target = methods_disp + " " + route_path
    return Finding(
        kind="rest",
        reach=reach,
        hook="rest",
        action=route_path,
        target=target,
        handler=cb_handler.display,
        resolved=(state != "unknown"),
        guards=guards,
        sinks=sinks,
        sink_level=level,
        verdict=verdict,
        severity=severity,
        reasons=reasons,
        file=unit.path,
        line=line,
    )


# --------------------------------------------------------------------------
# Per-file / whole-project driver
# --------------------------------------------------------------------------

def _analyze_unit(project, unit, stats):
    out = []
    sig = unit.sig
    for i, popen, pclose in _find_calls(unit, {"add_action", "add_filter"}):
        args = split_top_commas(sig, popen + 1, pclose)
        if len(args) < 2:
            continue
        hk = _classify_hook(sig, args[0])
        if hk is None:
            if sig[args[0][0]].kind != "str":
                stats.dynamic_hooks += 1
            continue
        handler = _resolve_callback(project, unit, args[1][0], args[1][1], i)
        hk["_line"] = sig[i].line
        f = _make_hook_finding(unit, hk, handler, stats)
        if f is not None:
            out.append(f)
    for i, popen, pclose in _find_calls(unit, {"register_rest_route"}):
        out.extend(_make_rest_findings(project, unit, i, popen, pclose))
    return out


def _gather_php_files(path):
    if os.path.isfile(path):
        return [os.path.abspath(path)] if path.endswith(".php") else []
    files = []
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for name in names:
            if name.endswith(".php"):
                files.append(os.path.abspath(os.path.join(root, name)))
    files.sort()
    return files


def build_project(paths):
    files = []
    seen = set()
    for p in paths:
        for f in _gather_php_files(p):
            if f not in seen:
                seen.add(f)
                files.append(f)
    units = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        tokens = tokenize(src)
        units.append(FileUnit(f, src, tokens, significant(tokens)))
    return Project(units)


def analyze(paths, root=None):
    """Scan ``paths`` (files or directories) and return a :class:`ScanResult`."""
    if isinstance(paths, str):
        paths = [paths]
    project = build_project(paths)
    stats = Stats(files_scanned=len(project.units))
    findings = []
    for unit in project.units:
        findings.extend(_analyze_unit(project, unit, stats))
    if root is None:
        root = os.path.abspath(paths[0]) if paths else ""
    return ScanResult(findings=findings, stats=stats, root=root)


def scan_path(path):
    """Convenience wrapper: analyze a single path."""
    return analyze([path], root=os.path.abspath(path))
