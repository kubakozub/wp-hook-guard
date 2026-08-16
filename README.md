# wp-hook-guard

[![tests](https://github.com/kubakozub/wp-hook-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/wp-hook-guard/actions/workflows/tests.yml)

**Find the WordPress plugin entry points that anyone can reach but nobody guarded.**

`wp-hook-guard` is a fast, dependency-free static analyzer that reads a WordPress
plugin or theme's PHP source, enumerates every server-side entry point a user (or
an *unauthenticated* visitor) can trigger, and flags the ones that are **missing an
authorization or nonce check**. That single bug class — *broken access control* —
covers most of the highest-impact WordPress vulnerabilities: privilege escalation,
CSRF, unauthenticated option/row writes, and public REST endpoints that should
never have been public.

It is a **triage aid for security researchers and plugin authors**, not a prover.
It gets you from "10,000 lines of unfamiliar plugin code" to "these six handlers
are reachable and unguarded — look here first" in well under a second.

- **Zero dependencies.** Pure Python 3.9+ standard library.
- **No network, no execution, no payloads.** It only reads source files.
- **High signal.** A custom PHP lexer means hooks mentioned in comments or strings
  never produce false hits, and handlers are resolved to their bodies across files.

> Companion to `wp-authz-audit`: where that tool audits authorization decisions,
> `wp-hook-guard` answers the prior question — *which entry points exist, and which
> are undefended in the first place?*

---

## Why this is the bug

WordPress exposes plugin code to the world through a small, well-known set of
registration hooks. Each one is an attacker-reachable entry point:

| Registration | Who can reach it | The guard you expect |
|---|---|---|
| `add_action('wp_ajax_nopriv_x', …)` | **Anyone, logged out** | a capability/auth check *and* a nonce |
| `add_action('wp_ajax_x', …)` | **Any logged-in user** (incl. Subscriber) | `current_user_can(...)` + nonce |
| `add_action('admin_post_nopriv_x', …)` | **Anyone, logged out** | capability/auth + nonce |
| `add_action('admin_post_x', …)` | **Any logged-in user** | `current_user_can(...)` + nonce |
| `register_rest_route(..., ['permission_callback' => …])` | depends entirely on the callback | a real `permission_callback` |
| `add_action('init' / 'wp_loaded', …)` reading `$_GET/$_POST` | **Anyone, logged out** | capability/auth + nonce |
| `add_action('admin_init', …)` reading `$_GET/$_POST` | **Any logged-in user** | capability + nonce |

The vulnerability is almost always an **omission**:

- A `wp_ajax_nopriv_` handler that calls `update_option()` / `$wpdb->query()` /
  `wp_insert_user()` **without** `current_user_can()` → unauthenticated state change.
- A `register_rest_route()` whose `permission_callback` is **`__return_true`** or
  **missing** → the route is world-writable. (WordPress has warned about missing
  `permission_callback` since 5.5, yet it remains one of the most common findings.)
- A handler that has a nonce but **no capability check** → any Subscriber can drive
  an admin-only action (privilege escalation).
- A handler with a capability check but **no nonce** → CSRF.

`wp-hook-guard` encodes exactly this reasoning: enumerate the entry points, resolve
each handler, and check whether the guard that its reachability demands is actually
present.

---

## Install

No dependencies, so you can just clone and run:

```bash
git clone https://github.com/jakubkozub/wp-hook-guard
cd wp-hook-guard
python -m wp_hook_guard scan /path/to/plugin
```

Or install the `wp-hook-guard` console command:

```bash
pip install .
wp-hook-guard scan /path/to/plugin
```

Requires **Python 3.9+**. That's it.

---

## Usage

```bash
# Scan a plugin directory (recursive) — readable table by default
python -m wp_hook_guard scan /path/to/wp-content/plugins/acme-widgets

# Focus on what matters: hide entry points that already look guarded
python -m wp_hook_guard scan ./acme-widgets --only-unguarded

# Only CRITICAL/HIGH, with full reasoning per finding
python -m wp_hook_guard scan ./acme-widgets --min-severity high --detail

# Machine-readable output for pipelines / notebooks
python -m wp_hook_guard scan ./acme-widgets --json > report.json

# CI gate: non-zero exit if anything HIGH or worse is found
python -m wp_hook_guard scan ./acme-widgets --fail-on high
```

### Sample output

```text
SEVERITY  VERDICT    REACH   KIND        ACTION / ROUTE               GUARDS                    LOCATION
--------  ---------  ------  ----------  ---------------------------  ------------------------  -----------
CRITICAL  UNGUARDED  unauth  ajax        vg_save_settings             -                         vuln.php:9
CRITICAL  UNGUARDED  unauth  rest        POST /vg/v1/wipe             permission:__return_true  vuln.php:38
HIGH      UNGUARDED  unauth  admin_post  vg_delete                    -                         vuln.php:18
HIGH      UNGUARDED  auth    ajax        vg_save_settings             -                         vuln.php:10
MEDIUM    UNGUARDED  unauth  init        vg_maybe_export  (via init)  -                         vuln.php:26

Scanned 1 file(s); found 5 entry point(s).
Severity: CRITICAL=2  HIGH=2  MEDIUM=1
Verdict:  UNGUARDED=5
```

`--detail` explains each verdict, including the sink that sets the severity:

```text
[CRITICAL] POST /vg/v1/wipe  (unauthenticated, UNGUARDED)
  hook:     rest
  handler:  vg_rest_wipe
  location: .../vuln.php:38
  guards:   permission:__return_true
  sinks:    delete_option  [dangerous]
  - permission_callback => __return_true (route is public)
  - REST route is reachable without authentication
```

---

## How to read the results

**REACH** — who can trigger the handler:

- `unauth` — reachable by an unauthenticated visitor (`*_nopriv_`, public REST,
  `init`/`wp_loaded`). Highest interest.
- `auth` — reachable by *any* logged-in user, including a Subscriber
  (`wp_ajax_`, `admin_post_`, `admin_init`). This is the classic privilege-escalation surface.

**VERDICT** — the guard assessment:

- `UNGUARDED` — reachable, performs a sensitive operation, and has **no capability/auth
  check** appropriate to its reach. This is the bug.
- `WEAK` — a guard exists but a real gap remains (e.g. capability present but **no nonce**
  on a state-changing handler → CSRF; or reachable but no sensitive sink was detected).
- `UNKNOWN` — the handler or `permission_callback` couldn't be resolved statically
  (dynamic callable, computed hook). Worth a manual look.
- `GUARDED` — an appropriate authorization check was found.

**SEVERITY** is a heuristic combining **reach × what the handler does** (its "sink"):

| | dangerous sink¹ | write sink² | read sink³ | no sink seen |
|---|---|---|---|---|
| **unauth** | CRITICAL | HIGH | MEDIUM | LOW |
| **auth** | HIGH | MEDIUM | LOW | LOW |

¹ `eval`/`exec`, file writes, `unserialize`, `update_option`, user creation, arbitrary
`include`, `call_user_func`, `wp_handle_upload`, …
² `wp_insert_post`, `*_meta`, `$wpdb->query/insert/update/delete`, outbound HTTP, `wp_mail`, …
³ `get_option`, `file_get_contents`, `get_users`, `$wpdb->get_*`, … (info disclosure)

A `current_user_can()` on an otherwise-unauthenticated handler downgrades its reach to
`auth` (and an `is_user_logged_in()` does the same, minus capability granularity), which
is reflected in the score.

---

## Fork / version-differential workflow

The fastest way to find a fresh bug in a mature plugin is to look at **what just
changed**. New code is unreviewed code; a refactor that moves a capability check is a
regression waiting to be reported. `wp-hook-guard diff` scans two trees and shows which
entry points were **added**, **removed**, or **changed** between them:

```bash
# Diff two release tags of the same plugin
python -m wp_hook_guard diff acme-widgets-4.1.0/ acme-widgets-4.2.0/

# Or compare a plugin against its fork
python -m wp_hook_guard diff upstream-plugin/ vendor-fork/
```

```text
=== Entry-point differential ===

+ ADDED (5)
  + [CRITICAL] UNGUARDED  vg_save_settings  <unauthenticated>  vuln.php:9
  + [CRITICAL] UNGUARDED  POST /vg/v1/wipe  <unauthenticated>  vuln.php:38
  ...

~ CHANGED (0)
  (none)

- REMOVED (3)
  - [INFO] sg_save_settings  <authenticated>
  ...

Focus: 5 newly-exposed and 0 regressed entry point(s).
```

The **Focus** line is the payoff: newly-exposed entry points and any that
**regressed from `GUARDED` to not-guarded** between versions — exactly the deltas worth
opening a diff for. Add `--json` to feed the comparison into other tooling, or
`--only-unguarded` to suppress guarded additions.

---

## Limitations

`wp-hook-guard` is a heuristic triage tool. PHP is not fully parsed or executed, so it
trades completeness for speed and low noise. Treat every finding as a **lead to verify**,
never as a confirmed vulnerability — and remember it can miss things.

Known blind spots (documented on purpose):

- **Indirection.** A guard implemented in a helper the handler *calls*
  (`$this->verify()`, a shared `require_auth()`) is not followed, so such a handler may be
  reported `UNGUARDED`. Conversely, a sink reached only through a called function may be
  missed, lowering severity.
- **Dynamic hooks & callables.** Hook names built at runtime (`"wp_ajax_" . $x`) and
  dynamic callbacks (`$this->cb`, variable function names) are reported as `UNKNOWN` or
  skipped — they can't be resolved statically.
- **Early-return / conditional guards.** A check that only runs on one code path, or that
  `wp_die()`s inside an `if`, is detected as *present* but its control flow is not modeled.
- **Custom capability logic.** Authorization performed without the standard WordPress
  functions (bespoke role math, option comparisons) is not recognized as a guard.
- **Nonce ≠ authorization.** A nonce prevents CSRF; it does **not** restrict *who* may act.
  The tool tracks the two separately, but the human decides whether a given nonce is
  actually reachable/secret in context.
- **Multi-block REST args.** In a `register_rest_route()` call that registers several
  methods with separate `callback`s, sink/impact is estimated from the first callback.

If a finding looks wrong, `--detail` shows the exact guards, sinks, and reasoning behind
it so you can confirm or dismiss it quickly.

---

## Responsible, authorized research only

This tool performs **static source analysis on code you already have**. It sends no
network traffic and produces no exploits. Use it only against software you are
**authorized** to review — your own plugins, code you are engaged to assess, or targets
covered by a bug-bounty program's scope and rules. Always follow coordinated-disclosure
practices when reporting what you find.

---

## Development

```bash
# Run the test suite (stdlib unittest, no dependencies)
python -m unittest discover -v
```

The `tests/fixtures/` directory contains small, synthetic plugins — one deliberately
vulnerable, one safe, plus class-based, REST, and lexer edge cases — used to pin the
scanner's behavior. They are original examples written for this project; no third-party
plugin code is included.

## License

MIT © 2026 Jakub Kozub. See [LICENSE](LICENSE).
