"""
Executes frontend/kite.html's JavaScript in a real V8 engine and
renders every view against representative state.

The console had no automated test at any level, which made it the one
part of the system where a change could only be checked by reading it.
That is also why it kept growing: nothing pushed back. This doesn't need
a browser, a build step, or a headless-Chrome dependency — the views are
pure functions from `state` to an HTML string, so the useful half can be
tested by calling them.

What this catches: syntax errors, typos in identifiers, referencing a
state field that doesn't exist, a template literal that throws on null,
and unescaped interpolation of user-controlled text. What it does not
catch: anything about layout, CSS, or real click behaviour — those still
need eyes on a browser, and this file does not pretend otherwise.
"""
import json
from datetime import datetime
import re
from pathlib import Path

import pytest

py_mini_racer = pytest.importorskip("py_mini_racer", reason="needs a JS engine to run the console")

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "kite.html"

# Minimal browser surface. Only what the render functions actually touch
# on the way to returning a string — deliberately not a DOM
# implementation, since anything needing a real DOM isn't testable here
# anyway and should be kept out of the render path.
DOM_STUB = """
var __els = {};
function __el(id){
  if(!__els[id]) __els[id] = {
    id: id, innerHTML: '', value: '', textContent: '', checked: false,
    selectionStart: 0, style: {}, dataset: {},
    classList: { add:function(){}, remove:function(){}, toggle:function(){}, contains:function(){return false} },
    focus: function(){}, setSelectionRange: function(){}, appendChild: function(){},
    removeChild: function(){}, addEventListener: function(){}, remove: function(){},
    querySelector: function(){ return null }, querySelectorAll: function(){ return [] },
  };
  return __els[id];
}
var document = {
  getElementById: function(id){ return __el(id) },
  querySelector: function(sel){ return __el(sel) },
  querySelectorAll: function(){ return [] },
  createElement: function(){ return __el('__created__' + Math.random()) },
  addEventListener: function(){}, removeEventListener: function(){},
  body: __el('body'),
};
var location = { hash: '', host: 'kite.example.com', protocol: 'https:', reload: function(){} };
var window = { location: location, addEventListener: function(){}, scrollTo: function(){} };
var navigator = { clipboard: { writeText: function(){ return Promise.resolve() } } };
function setInterval(){ return 1 } function clearInterval(){}
function setTimeout(fn){ return 1 } function clearTimeout(){}
function fetch(){ return Promise.reject(new Error('network disabled in tests')) }
function FormData(){ this.append = function(){} }
function alert(){} function confirm(){ return true }
"""


def _script_paths():
    """
    The console is split across files with no module system, so load
    order is load-bearing (see kite.html's comment). Read the order
    from the HTML itself rather than hardcoding it here — that way this
    harness exercises the same sequence a browser does, and a file added
    to one and not the other fails loudly.
    """
    html = FRONTEND.read_text()
    srcs = re.findall(r'<script src="/ui/([^"]+)"></script>', html)
    assert srcs, "no <script src> tags found in kite.html"
    return [FRONTEND.parent / src for src in srcs]


def _extract_js() -> str:
    parts = []
    for path in _script_paths():
        assert path.is_file(), f"{path} is referenced by kite.html but does not exist"
        parts.append(path.read_text())
    return "\n".join(parts)


@pytest.fixture(scope="module")
def js():
    """One V8 context with the console's JS loaded. Module-scoped: parsing
    is the expensive part and no test here mutates global state it cares
    about carrying between tests (each sets `state` explicitly)."""
    ctx = py_mini_racer.MiniRacer()
    ctx.eval(DOM_STUB)
    ctx.eval(_extract_js())
    return ctx


def _render(js, view: str, state_patch: dict) -> str:
    """Apply a patch over the app's own default state, then render one view."""
    js.eval(f"Object.assign(state, {json.dumps(state_patch)});")
    return js.eval(f"{view}()")


# Representative data, shaped like what the API actually returns.
HOSTS = [
    {"id": 1, "hostname": "web-01", "role": "web", "team": "platform", "os_family": "rocky9",
     "os_version": "Rocky 9", "smbios_uuid": "", "poll_interval_seconds": 900,
     "proxmox_vmid": 101, "proxmox_node": None, "rollback_backend": None, "agent_version": "0.1.6",
     "last_seen": "2026-09-05T12:00:00", "last_patched": "2026-09-01T00:00:00",
     "status": "healthy", "active_job_id": None},
    {"id": 2, "hostname": "win-01", "role": "file", "team": "corporate", "os_family": "win2022",
     "os_version": "Server 2022", "smbios_uuid": "", "poll_interval_seconds": 900,
     "proxmox_vmid": None, "proxmox_node": None, "rollback_backend": None, "agent_version": "",
     "last_seen": None, "last_patched": None, "status": "unknown", "active_job_id": None},
]

DASHBOARD = {
    "generated_at": "2026-09-05T12:00:00",
    "fleet": {"total": 2, "healthy": 1, "stale": 0, "offline": 1, "compliance_pct": 50,
              "never_patched": 1, "overdue": 0, "avg_days_since_patched": 4,
              "by_platform": {"linux": 1, "windows": 1},
              "by_team": {"platform": 1, "corporate": 1}},
    "runs": {"active": 1, "completed_24h": 3, "failed_24h": 1, "stuck": 0},
    "attention": [{"host_id": 2, "hostname": "win-01", "reason": "offline", "tone": "danger"}],
    "activity": [{"ts": "2026-09-05T11:00:00", "actor": "dev", "action": "run_completed",
                  "detail": "web-01 — job 41", "tone": "success"}],
    "active_runs": [{"job_id": 42, "hostname": "web-01", "stage": "patch", "stage_index": 3,
                     "total_stages": 7, "started_at": "2026-09-05T11:55:00"}],
    "upcoming": [{"id": 1, "name": "Weekly platform", "team": "platform", "day_name": "Tuesday",
                  "hour": 3, "next_fire": "2026-09-08T03:00:00", "host_count": 1}],
    "agent_versions": {"0.1.6": 1, "unreported": 1},
    "risk": {"total": 12, "security": 9,
             "by_severity": {"critical": 2, "important": 4, "moderate": 3, "none": 3},
             "hosts_with_critical": 1, "hosts_with_important": 2, "unassessed": 1,
             "worst_hosts": [{"host_id": 1, "hostname": "web-01", "critical": 2,
                              "important": 1, "total": 7}]},
    "containers": {"total": 6, "hosts_with_containers": 2, "outdated": 2, "unknown": 1,
                   "pinned": 1, "by_management": {"compose": 4, "standalone": 2},
                   "worst_hosts": [{"host_id": 1, "hostname": "web-01", "outdated": 2}]},
}

CONTAINERS = [
    {"id": 1, "name": "shop-web", "image": "nginx:latest", "state": "running",
     "managed_by": "compose", "compose_project": "shop", "pinned": False,
     "update_available": True, "reported_at": "2026-09-05T12:00:00"},
    {"id": 2, "name": "shop-db", "image": "postgres@sha256:abc", "state": "running",
     "managed_by": "compose", "compose_project": "shop", "pinned": True,
     "update_available": False, "reported_at": "2026-09-05T12:00:00"},
    {"id": 3, "name": "private-app", "image": "reg.internal/app:latest", "state": "running",
     "managed_by": "standalone", "compose_project": "", "pinned": False,
     "update_available": None, "reported_at": "2026-09-05T12:00:00"},
]

ADMIN = {"username": "admin", "role": "admin", "display_name": "Admin"}
OPERATOR = {"username": "op", "role": "operator", "display_name": "Op"}
VIEWER = {"username": "auditor", "role": "viewer", "display_name": "Auditor"}


def test_the_console_javascript_parses(js):
    """The cheapest and most valuable assertion here: a syntax error in a
    2,000+ line inline script breaks every page at once, silently."""
    assert js.eval("typeof render") == "function"


@pytest.mark.parametrize("view,patch", [
    ("renderHome", {"user": ADMIN, "dashboard": DASHBOARD}),
    ("renderFleet", {"user": ADMIN, "fleet": HOSTS}),
    ("renderDefs", {"user": ADMIN, "defs": []}),
    ("renderScripts", {"user": ADMIN, "osScripts": []}),
    ("renderSchedules", {"user": ADMIN, "schedules": [], "tickets": [], "fleet": HOSTS}),
    ("renderAudit", {"user": ADMIN, "auditLog": []}),
    ("renderSettings", {"user": ADMIN, "settings": {}, "users": [], "checklistItems": []}),
    ("renderLogin", {"user": None}),
    ("renderCoverage", {"user": ADMIN, "fleetSection": "coverage", "coverage": None}),
    ("renderTopology", {"user": ADMIN, "topology": None}),
])
def test_every_view_renders_without_throwing(js, view, patch):
    html = _render(js, view, patch)
    assert isinstance(html, str) and html.strip(), f"{view} produced nothing"


@pytest.mark.parametrize("view,patch", [
    ("renderHome", {"user": ADMIN, "dashboard": None}),
    ("renderFleet", {"user": ADMIN, "fleet": None}),
    ("renderDefs", {"user": ADMIN, "defs": None}),
    ("renderScripts", {"user": ADMIN, "osScripts": None}),
    ("renderAudit", {"user": ADMIN, "auditLog": None}),
])
def test_views_render_their_loading_state(js, view, patch):
    """null means "not fetched yet" throughout this app — every view has
    to survive being rendered before its data arrives, which is exactly
    what happens on first paint."""
    assert _render(js, view, patch).strip()


def test_home_renders_the_empty_fleet_state(js):
    empty = dict(DASHBOARD, fleet=dict(DASHBOARD["fleet"], total=0, healthy=0, offline=0,
                                        compliance_pct=100, never_patched=0,
                                        by_platform={}, by_team={}),
                 attention=[], active_runs=[], activity=[], upcoming=[], agent_versions={})
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": empty})
    assert "enroll" in html.lower(), "empty dashboard should point somewhere useful"


def test_home_shows_the_headline_numbers(js):
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": DASHBOARD})
    assert "web-01" in html              # worst-off table + active run
    assert "run_completed" in html       # activity feed
    assert "Worst off right now" in html
    assert "Activity" in html


def test_home_active_run_progress_is_within_bounds(js):
    """A stage index at or past the end must not produce a >100% bar."""
    finishing = dict(DASHBOARD, active_runs=[
        {"job_id": 1, "hostname": "h", "stage": "finishing", "stage_index": 7,
         "total_stages": 7, "started_at": None}])
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": finishing})
    widths = [float(w) for w in re.findall(r"width:([\d.]+)%", html)]
    assert widths, "expected a progress bar"
    assert all(0 <= w <= 100 for w in widths), widths


def test_hostname_is_escaped_not_interpolated_raw(js):
    """
    Hostnames come from an enrolling agent, so they're attacker-influenced
    in exactly the way that matters for the fleet table.
    """
    hostile = [dict(HOSTS[0], id=9, hostname='<img src=x onerror="alert(1)">')]
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": hostile})
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


def test_activity_detail_is_escaped(js):
    hostile = dict(DASHBOARD, activity=[
        {"ts": "2026-09-05T11:00:00", "actor": "<b>x</b>", "action": "login",
         "detail": "<script>alert(1)</script>", "tone": "neutral"}])
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": hostile})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


def _visible_nav(js, user):
    js.eval(f"Object.assign(state, {json.dumps({'user': user})});")
    # via JSON: MiniRacer hands back an opaque JSObject for a raw array.
    return json.loads(js.eval(
        "JSON.stringify(Object.keys(navItems).filter(id => !navItems[id].minRole || atLeast(state.user.role, navItems[id].minRole)))"))


def test_nav_follows_role(js):
    """Cosmetic only — the server enforces this for real (see app/auth.py)
    — but a nav item that 403s on click is a bad console. Settings is open
    to every role because API tokens live there; renderSettings() shows a
    non-admin that one tab only."""
    assert {"settings", "topology", "run"} <= set(_visible_nav(js, OPERATOR))
    viewer = _visible_nav(js, VIEWER)
    assert "run" not in viewer
    assert {"home", "fleet", "topology", "settings"} <= set(viewer)


def test_non_admin_settings_shows_only_api_tokens(js):
    html = _render(js, "renderSettings", {"user": OPERATOR, "settingsTab": "policy", "apiTokens": [], "tokenCreated": None})
    assert "Create token" in html
    assert "Require an approved ticket" not in html
    assert "Users &amp; roles" not in html and "Users & roles" not in html


def test_connectivity_tiers_match_the_backend(js):
    """
    connectivityTier() in the frontend and connectivity_tier() in
    app/monitoring.py are the same formula maintained in two places (the
    monitoring module says so). Pin the thresholds here so the copies
    can't drift silently: stale past 2x the poll interval, offline past 4x.
    """
    js.eval("state.__now = 0")
    assert js.eval("connectivityTier({last_seen: null, poll_interval_seconds: 900})") == "offline"
    now_ms = "Date.now()"
    for age_sec, expected in [(60, "healthy"), (1900, "stale"), (4000, "offline")]:
        iso = js.eval(f"new Date({now_ms} - {age_sec} * 1000).toISOString()")
        got = js.eval(f"connectivityTier({{last_seen: {json.dumps(iso)}, poll_interval_seconds: 900}})")
        assert got == expected, f"{age_sec}s since last seen -> {got}, expected {expected}"


def test_until_time_reads_forward_not_clamped_to_now(js):
    """
    relTime() clamps negative ages to zero, so reusing it for a future
    timestamp made every future time read "just now". untilTime() is the
    counterpart that reads forward. Tested directly now that the Overview's
    upcoming-schedule card (its old caller) lives on the Schedules page.
    """
    assert js.eval("untilTime(new Date(Date.now() + 3 * 3600 * 1000).toISOString())") == "in 3h"
    assert js.eval("untilTime(new Date(Date.now() - 3 * 3600 * 1000).toISOString())") == "due now"


def test_rel_and_until_are_symmetric_around_now(js):
    past = js.eval("new Date(Date.now() - 2 * 3600 * 1000).toISOString()")
    future = js.eval("new Date(Date.now() + 2 * 3600 * 1000).toISOString()")
    assert js.eval(f"relTime({json.dumps(past)})") == "2h ago"
    assert js.eval(f"untilTime({json.dumps(future)})") == "in 2h"
    # A schedule whose slot is essentially now reads as due, not overdue.
    assert js.eval(f"untilTime({json.dumps(past)})") == "due now"


def _all_rendered_html(js) -> str:
    """Every view's output concatenated, for whole-file structural checks."""
    views = [
        ("renderHome", {"user": ADMIN, "dashboard": DASHBOARD}),
        ("renderFleet", {"user": ADMIN, "fleet": HOSTS}),
        ("renderDefs", {"user": ADMIN, "defs": []}),
        ("renderScripts", {"user": ADMIN, "osScripts": []}),
        ("renderSchedules", {"user": ADMIN, "schedules": [], "tickets": [], "fleet": HOSTS}),
        ("renderAudit", {"user": ADMIN, "auditLog": []}),
        ("renderSettings", {"user": ADMIN, "settings": {}, "users": [], "checklistItems": []}),
        ("renderLogin", {"user": None}),
    ]
    return "\n".join(_render(js, view, patch) for view, patch in views)


def test_no_element_carries_two_class_attributes(js):
    """
    A browser keeps the FIRST class attribute and silently discards the
    second, so `class="mono" class="muted"` loses the colour with no
    error anywhere. Easy to introduce when converting an inline style on
    an element that already had a class.
    """
    offenders = re.findall(r'<[a-z]+[^<>]*?class="[^"]*"[^<>]*?class="[^"]*"[^<>]*>', _all_rendered_html(js))
    assert not offenders, offenders[:5]


def test_source_has_no_duplicate_class_attributes():
    """Same check against the file itself, so it also covers the static
    markup and the branches no fixture happens to render."""
    source = FRONTEND.read_text() + "\n".join(p.read_text() for p in _script_paths())
    offenders = re.findall(r'class="[^"]*"[^<>]*?class="[^"]*"', source)
    assert not offenders, offenders[:5]


def test_every_js_file_on_disk_is_loaded_by_the_page():
    """
    With no module system, a file nobody references is dead code that
    still looks alive — and a view moved into one would simply never
    run, with no error anywhere.
    """
    referenced = {p.resolve() for p in _script_paths()}
    on_disk = {p.resolve() for p in (FRONTEND.parent / "js").rglob("*.js")}
    assert on_disk - referenced == set(), f"not referenced by kite.html: {on_disk - referenced}"
    assert referenced - on_disk == set(), f"referenced but missing: {referenced - on_disk}"


def test_the_stylesheet_is_referenced_and_present():
    html = FRONTEND.read_text()
    hrefs = re.findall(r'<link rel="stylesheet" href="/ui/([^"]+)"', html)
    assert hrefs, "no stylesheet linked"
    for href in hrefs:
        assert (FRONTEND.parent / href).is_file(), href


# ---------- container inventory ----------
# The Overview's fleet-wide container card was removed in the console
# redesign — the mockup's Overview right rail is Activity only, and
# container position lives on the host-detail page (tested below). The
# home tests that follow only assert the page still renders regardless of
# the payload's `containers` key.

def test_home_survives_a_controller_without_container_support(js):
    """An older controller returns no `containers` key at all."""
    payload = {k: v for k, v in DASHBOARD.items() if k != "containers"}
    assert _render(js, "renderHome", {"user": ADMIN, "dashboard": payload}).strip()


def test_host_containers_render_all_three_states(js):
    html = _render(js, "renderHostContainers",
                   {"user": ADMIN, "hostContainers": CONTAINERS})
    assert "update available" in html      # True
    assert "pinned" in html                # digest-pinned
    assert "not determined" in html        # None
    assert "up to date" not in html        # nothing here is demonstrably current


def test_undetermined_is_never_rendered_as_up_to_date(js):
    """The claim that must not be made: an unread registry is not a
    guarantee the image is current."""
    unknown_only = [dict(CONTAINERS[2])]
    html = _render(js, "renderHostContainers",
                   {"user": ADMIN, "hostContainers": unknown_only})
    assert "not determined" in html
    assert "up to date" not in html


def test_host_container_section_is_absent_before_it_loads(js):
    assert _render(js, "renderHostContainers", {"user": ADMIN, "hostContainers": None}) == ""
    assert _render(js, "renderHostContainers", {"user": ADMIN, "hostContainers": []}) == ""


def test_container_names_and_images_are_escaped(js):
    hostile = [dict(CONTAINERS[0], name='<img src=x onerror=alert(1)>',
                    image='<script>alert(2)</script>')]
    html = _render(js, "renderHostContainers", {"user": ADMIN, "hostContainers": hostile})
    assert "<img src=x" not in html
    assert "<script>alert(2)</script>" not in html
    assert "&lt;img src=x" in html


# ---------- run scope picker ----------

RUN_CONTAINERS = [
    {"id": 1, "name": "shop-web", "image": "nginx:latest", "state": "running",
     "managed_by": "compose", "compose_project": "shop", "compose_service": "web",
     "pinned": False, "update_available": True, "updatable": True},
    {"id": 2, "name": "shop-api", "image": "app:1.2", "state": "running",
     "managed_by": "compose", "compose_project": "shop", "compose_service": "api",
     "pinned": False, "update_available": False, "updatable": True},
]


def test_scope_picker_offers_all_three_scopes(js):
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "os", "runContainers": RUN_CONTAINERS,
                    "runContainerPick": None})
    for label in ("OS packages", "Containers only", "Both"):
        assert label in html


def test_container_list_appears_only_when_the_scope_includes_them(js):
    base = {"user": ADMIN, "runContainers": RUN_CONTAINERS, "runContainerPick": None}
    os_only = _render(js, "renderScopePicker", dict(base, runScope="os"))
    with_containers = _render(js, "renderScopePicker", dict(base, runScope="containers"))

    assert "shop-web" not in os_only
    assert "shop-web" in with_containers


def test_scope_picker_explains_a_host_with_nothing_updatable(js):
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "containers", "runContainers": [],
                    "runContainerPick": None})
    assert "No compose-managed containers" in html
    assert "orchestrator" in html


def test_scope_picker_shows_a_loading_state(js):
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "os", "runContainers": None,
                    "runContainerPick": None})
    assert "Checking what this host runs" in html


def test_no_explicit_selection_means_all_updatable(js):
    js.eval(f"Object.assign(state, {{runContainers: {json.dumps(RUN_CONTAINERS)}, runContainerPick: null}});")
    assert json.loads(js.eval("JSON.stringify(runContainerSelection())")) == []


def test_a_narrowed_selection_is_sent_explicitly(js):
    js.eval(f"Object.assign(state, {{runContainers: {json.dumps(RUN_CONTAINERS)}, runContainerPick: null}});")
    js.eval("toggleRunContainer('shop-api')")   # start from all, drop one
    picked = json.loads(js.eval("JSON.stringify(runContainerSelection())"))
    assert picked == ["shop-web"]


def test_container_names_in_the_picker_are_escaped(js):
    hostile = [dict(RUN_CONTAINERS[0], name='<img src=x onerror=alert(1)>')]
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "containers", "runContainers": hostile,
                    "runContainerPick": None})
    assert "<img src=x" not in html


def test_schedule_rows_show_their_scope(js):
    schedules = [
        {"id": 1, "name": "OS weekly", "team": "", "day_of_week": 1, "hour": 3,
         "enabled": True, "ticket_id": None, "created_by": "dev",
         "last_fired_at": None, "scope": "os"},
        {"id": 2, "name": "Images nightly", "team": "platform", "day_of_week": 2, "hour": 4,
         "enabled": True, "ticket_id": None, "created_by": "dev",
         "last_fired_at": None, "scope": "containers"},
    ]
    html = _render(js, "renderSchedules",
                   {"user": ADMIN, "schedules": schedules, "tickets": [], "fleet": HOSTS})
    assert "containers" in html
    assert "OS weekly" in html


def test_a_schedule_without_a_scope_reads_as_os(js):
    """Schedules created before scopes existed have none; they patched
    the OS, and must keep saying so."""
    legacy = [{"id": 1, "name": "legacy", "team": "", "day_of_week": 1, "hour": 3,
               "enabled": True, "ticket_id": None, "created_by": "dev", "last_fired_at": None}]
    html = _render(js, "renderSchedules",
                   {"user": ADMIN, "schedules": legacy, "tickets": [], "fleet": HOSTS})
    assert ">OS<" in html


def test_a_container_with_a_capture_offers_rollback(js):
    with_capture = [dict(CONTAINERS[0], rollback_available=True,
                         rollback_captured_at="2026-09-05T10:00:00")]
    html = _render(js, "renderHostContainers",
                   {"user": ADMIN, "hostContainers": with_capture,
                    "hostDetail": {"host": {"id": 7}, "runs": []}})
    assert "Roll back" in html


def test_a_container_without_a_capture_says_so(js):
    without = [dict(CONTAINERS[0], rollback_available=False)]
    html = _render(js, "renderHostContainers",
                   {"user": ADMIN, "hostContainers": without,
                    "hostDetail": {"host": {"id": 7}, "runs": []}})
    assert "no capture" in html
    assert "Roll back" not in html


# ---------- risk ----------

UPDATES = [
    {"package": "openssl", "new_version": "3.2.2-6", "advisory": "RLSA-2026:1",
     "severity": "critical", "is_security": True},
    {"package": "curl", "new_version": "8.6.0-2", "advisory": "RLSA-2026:2",
     "severity": "moderate", "is_security": True},
    {"package": "libpcre2-8-0", "new_version": "10.42-1+deb12u1",
     "advisory": "oldstable-security", "severity": "unknown", "is_security": True},
    {"package": "tzdata", "new_version": "2024a", "advisory": "", "severity": "none",
     "is_security": False},
]


def test_home_shows_the_risk_card(js):
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": DASHBOARD})
    # Risk is surfaced as the Urgent-waiting tile and the worst-off list.
    assert "Urgent waiting" in html
    assert "Worst off" in html


def test_unassessed_hosts_are_surfaced_not_hidden(js):
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": DASHBOARD})
    # The hatched tile — unknown, not zero, excluded from the reachable %.
    assert "Couldn't check" in html


def test_home_survives_a_controller_without_risk_support(js):
    payload = {k: v for k, v in DASHBOARD.items() if k != "risk"}
    assert _render(js, "renderHome", {"user": ADMIN, "dashboard": payload}).strip()


def test_a_clean_fleet_says_so_rather_than_showing_zeroes(js):
    clean = dict(DASHBOARD, risk=dict(DASHBOARD["risk"], total=0, security=0,
                                       by_severity={}, hosts_with_critical=0,
                                       unassessed=0, worst_hosts=[]))
    html = _render(js, "renderHome", {"user": ADMIN, "dashboard": clean})
    assert "every assessed host is current" in html


def test_host_updates_render_every_severity(js):
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": UPDATES,
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": True}, "runs": []}})
    for label in ("Critical", "Moderate", "Security", "Non-security"):
        assert label in html


def test_an_unqueryable_host_says_unknown_not_patched(js):
    """The claim that must never be made: silence is not a clean bill of
    health."""
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": [],
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": False}, "runs": []}})
    assert "could not be queried" in html
    assert "No pending updates" not in html


def test_a_genuinely_clean_host_says_so(js):
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": [],
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": True}, "runs": []}})
    assert "No pending updates reported" in html


def test_package_names_in_the_update_list_are_escaped(js):
    hostile = [dict(UPDATES[0], package='<img src=x onerror=alert(1)>')]
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": hostile,
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": True}, "runs": []}})
    assert "<img src=x" not in html


def test_the_run_wizard_offers_severity_bands(js):
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "os", "runContainers": [],
                    "runContainerPick": None, "runSeverity": ""})
    for label in ("Everything", "Security only", "Critical + Important", "Critical only"):
        assert label in html


def test_severity_bands_are_hidden_on_a_containers_only_run(js):
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "containers", "runContainers": [],
                    "runContainerPick": None, "runSeverity": ""})
    assert "Security only" not in html


def test_choosing_a_severity_warns_about_apt(js):
    """apt has no per-advisory severity, so the band cannot be honoured
    there — better said up front than discovered in stage output."""
    html = _render(js, "renderScopePicker",
                   {"user": ADMIN, "runScope": "os", "runContainers": [],
                    "runContainerPick": None, "runSeverity": "critical"})
    assert "no per-advisory severity" in html


# ---------- fleet risk column ----------

def _fleet_host(**kw):
    base = dict(HOSTS[0])
    base.update(kw)
    return base


def test_fleet_risk_sorts_worst_first_and_by_volume(js):
    """A single numeric key: the comparator uses `<`, and array keys
    would be compared as strings, which is not numeric order."""
    hosts = [
        _fleet_host(id=1, hostname="clean", max_severity="none", pending_updates=0,
                    updates_assessed_ok=True),
        _fleet_host(id=2, hostname="many-moderate", max_severity="moderate",
                    pending_updates=45, updates_assessed_ok=True),
        _fleet_host(id=3, hostname="few-moderate", max_severity="moderate",
                    pending_updates=3, updates_assessed_ok=True),
        _fleet_host(id=4, hostname="one-critical", max_severity="critical",
                    pending_updates=1, updates_assessed_ok=True),
    ]
    js.eval(f"Object.assign(state, {{fleet: {json.dumps(hosts)}}});")
    keys = json.loads(js.eval(
        "JSON.stringify(state.fleet.map(h => [h.hostname, FLEET_SORT_KEYS.risk(h)]))"))
    ordered = [name for name, _ in sorted(keys, key=lambda kv: kv[1])]

    assert ordered[0] == "one-critical", "severity outranks volume"
    assert ordered.index("many-moderate") < ordered.index("few-moderate"), \
        "within a severity, more pending sorts first"
    assert ordered[-1] == "clean"


def test_an_unqueryable_host_is_not_sorted_as_clean(js):
    hosts = [
        _fleet_host(id=1, hostname="clean", max_severity="none", pending_updates=0,
                    updates_assessed_ok=True),
        _fleet_host(id=2, hostname="unknown", max_severity="none", pending_updates=0,
                    updates_assessed_ok=False),
    ]
    js.eval(f"Object.assign(state, {{fleet: {json.dumps(hosts)}}});")
    keys = json.loads(js.eval(
        "JSON.stringify(state.fleet.map(h => [h.hostname, FLEET_SORT_KEYS.risk(h)]))"))
    ordered = [name for name, _ in sorted(keys, key=lambda kv: kv[1])]

    assert ordered[0] == "unknown"


def test_fleet_shows_unknown_rather_than_a_clean_dash(js):
    hosts = [_fleet_host(id=1, hostname="broken", max_severity="none",
                         pending_updates=0, updates_assessed_ok=False)]
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": hosts})
    assert "unknown" in html


def test_fleet_shows_the_worst_severity_and_count(js):
    hosts = [_fleet_host(id=1, hostname="risky", max_severity="critical",
                         pending_updates=7, updates_assessed_ok=True)]
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": hosts})
    # Severity now renders as a compact chip (CRIT) alongside the count.
    assert "CRIT" in html and "7" in html


LINUX_BUNDLE_STAGED = {
    "platform": "linux", "label": "Ubuntu / Debian (source bundle)",
    "filename": "kite-agent-linux.tar.gz", "available": True,
    "url": "/download/agent-linux", "size_bytes": 40_000,
    "sha256": "c" * 64, "built_at": "2026-09-06T09:00:00", "build_command": None,
}

LINUX_BUNDLE_MISSING = dict(LINUX_BUNDLE_STAGED, available=False, size_bytes=None,
                            sha256=None, built_at=None,
                            build_command="build-release.sh (or copy agent-linux/ there)")


def _drawer_state(platform, downloads=None):
    """State with the Add-machine drawer open on a generated token. This is
    the live enrolment path; the old host-detail enroll panel it replaced is
    gone, so these assertions follow the drawer."""
    return {
        "user": ADMIN,
        "agentDownloads": downloads,
        "addMachine": {
            "platform": platform, "hostname": "web-01", "team": "", "role": "",
            "result": {"token": "tok-123", "hostname": "web-01",
                       "expires_at": "2026-09-06T12:00:00"},
            "pollHandle": None, "baselineSeen": None,
        },
    }


def _eval_with(js, expr, state_patch):
    js.eval(f"Object.assign(state, {json.dumps(state_patch)});")
    return js.eval(expr)


def _download_html(js, platform, downloads):
    return _eval_with(js, "addMachineDownload(state.addMachine)",
                      _drawer_state(platform, downloads))


def test_the_enrollment_command_cannot_break_dnf_on_the_host(js):
    """
    Without skip_if_unavailable, dnf treats an unreachable repository as
    a hard error — so a controller that is down would break every dnf
    command on every managed host, `dnf update` included.
    """
    cmd = _eval_with(js, "enrollCommand('rhel', state.addMachine.result)",
                     _drawer_state("rhel"))
    assert "skip_if_unavailable=1" in cmd


WINDOWS_BUILD = [{
    "platform": "windows", "label": "Windows Server / 10 / 11 (x86-64)",
    "filename": "kite-agent.exe", "available": True,
    "url": "/download/agent/windows", "size_bytes": 9_100_000,
    "sha256": "a" * 64, "built_at": "2026-09-06T09:00:00", "build_command": None,
    "installer_filename": "kite-agent-setup.exe", "installer_available": True,
    "installer_url": "/download/installer/windows", "installer_size_bytes": 13_000_000,
    "installer_sha256": "b" * 64,
}]

WINDOWS_NOT_BUILT = [{
    "platform": "windows", "label": "Windows Server / 10 / 11 (x86-64)",
    "filename": "kite-agent.exe", "available": False,
    "url": "/download/agent/windows", "size_bytes": None,
    "sha256": None, "built_at": None, "build_command": "agent-windows/build.sh",
    "installer_filename": "kite-agent-setup.exe", "installer_available": False,
    "installer_url": "/download/installer/windows", "installer_size_bytes": None,
    "installer_sha256": None,
}]


def test_add_machine_offers_the_windows_installer_when_it_is_built(js):
    """
    The point of the whole mechanism: the operator gets a file that already
    knows the controller and carries the token, so nothing is typed on the
    host and nothing can be mistyped.
    """
    html = _download_html(js, "windows", WINDOWS_BUILD)
    assert "/download/installer/windows?token=tok-123" in html


def test_add_machine_says_an_unbuilt_windows_installer_is_unbuilt(js):
    """
    "Not built on this controller" and "not supported" are different
    answers. A dead download link says the second. This link used to render
    unconditionally and 404 where build.sh had never run.
    """
    html = _download_html(js, "windows", WINDOWS_NOT_BUILT)
    assert "agent-windows/build.sh" in html
    assert "?token=tok-123" not in html


def test_add_machine_reports_a_failed_download_check(js):
    html = _download_html(js, "windows", {"error": "503 Service Unavailable"})
    assert "503" in html
    # Not a download button: we do not know whether there is one to offer.
    assert "/download/installer/windows" not in html


def test_add_machine_offers_the_linux_bundle_only_when_staged(js):
    staged = _download_html(js, "rhel", [LINUX_BUNDLE_STAGED])
    assert "/download/agent-linux" in staged

    missing = _download_html(js, "rhel", [LINUX_BUNDLE_MISSING])
    assert "/download/agent-linux" not in missing, "offered a bundle this controller hasn't got"
    assert "build-release.sh" in missing


def test_enrollment_commands_use_the_page_scheme(js):
    """
    The controller is reached over https in most installs. Hardcoding
    http:// produced a download URL and a repo baseurl that simply did
    not answer.
    """
    for platform in ("rhel", "debian", "windows"):
        cmd = _eval_with(
            js,
            f"enrollCommand({json.dumps(platform)}, state.addMachine.result)",
            _drawer_state(platform),
        )
        assert "https://kite.example.com" in cmd, platform
        assert "http://kite.example.com" not in cmd, platform


def test_debian_enrollment_actually_enrols(js):
    """
    install-debian.sh only lays the files down — it reads no token and
    performs no enrolment. A command that stopped there would leave a
    host with an installed agent that never contacts anything.
    """
    cmd = _eval_with(js, "enrollCommand('debian', state.addMachine.result)",
                     _drawer_state("debian"))
    assert "install-debian.sh" in cmd
    assert "enroll.py" in cmd and "tok-123" in cmd
    assert "systemctl enable --now kite-agent" in cmd


def test_windows_enrollment_falls_back_to_a_command(js):
    """
    A host that cannot reach the console still needs a path in. The silent
    switches drive the same installer, so it cannot drift from the wizard.
    """
    cmd = _eval_with(js, "enrollCommand('windows', state.addMachine.result)",
                     _drawer_state("windows"))
    assert "/download/installer/windows" in cmd
    assert "/S /controller=" in cmd and "tok-123" in cmd


def test_an_unassessed_host_shows_why(js):
    """
    The controller knows the reason. Rendering only "unknown" makes an
    operator go read a log for something already on screen's doorstep.
    """
    host = dict(HOSTS[0], updates_assessed_ok=False,
                updates_error="Cannot download repomd.xml: All mirrors were tried")
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostDetail": {"host": host}, "hostUpdates": []})
    assert "could not be queried" in html
    assert "All mirrors were tried" in html


def test_an_unassessed_host_with_no_reason_says_so(js):
    host = dict(HOSTS[0], updates_assessed_ok=False, updates_error="")
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostDetail": {"host": host}, "hostUpdates": []})
    assert "could not be queried" in html
    # Not silence, and not a fabricated reason.
    assert "no reason" in html


THIRD_PARTY_UPDATES = [
    {"package": "openssl", "new_version": "3.2.2-6", "advisory": "RLSA-2026:1",
     "severity": "critical", "is_security": True, "source": "os", "current_version": ""},
    {"package": "Google Chrome", "new_version": "117.0", "advisory": "Google.Chrome",
     "severity": "none", "is_security": False, "source": "winget", "current_version": "116.0"},
    {"package": "org.mozilla.firefox", "new_version": "122.0", "advisory": "",
     "severity": "none", "is_security": False, "source": "flatpak", "current_version": "121.0"},
]


def test_updates_are_grouped_by_source(js):
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": THIRD_PARTY_UPDATES,
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": True}, "runs": []}})
    # Each source gets its own labelled group.
    assert "Operating system" in html
    assert "winget" in html
    assert "Flatpak" in html
    # A third-party app shows current -> available, not just a target.
    assert "116.0" in html and "117.0" in html


def test_a_source_the_console_does_not_name_is_still_shown(js):
    rows = [{"package": "some-app", "new_version": "2.0", "advisory": "", "severity": "none",
             "is_security": False, "source": "brew", "current_version": "1.0"}]
    html = _render(js, "renderHostUpdates",
                   {"user": ADMIN, "hostUpdates": rows,
                    "hostDetail": {"host": {"id": 1, "updates_assessed_ok": True}, "runs": []}})
    assert "brew" in html and "some-app" in html


# ---------- API tokens, Proxmox coverage, topology ----------

TOKENS = [
    {"id": 1, "name": "desktop-assistant", "prefix": "kite_ab12", "scope": "read", "username": "admin",
     "created_at": "2026-10-02T10:00:00", "expires_at": "2099-01-01T00:00:00",
     "last_used_at": "2026-10-19T10:00:00", "expired": False},
    {"id": 2, "name": "ci-reporting", "prefix": "kite_0d44", "scope": "read", "username": "op",
     "created_at": "2026-04-17T10:00:00", "expires_at": "2026-07-16T00:00:00",
     "last_used_at": None, "expired": True},
]
PM_OK = {"configured": True, "host": "pve.lab", "nodes": 2, "error": "", "stale": False,
         "fetched_at": "2026-10-19T10:00:00", "cached": False}


def _guest(vmid, name, coverage, node="pve1", type_="qemu", status="running", **extra):
    return dict({"vmid": vmid, "name": name, "node": node, "type": type_, "status": status,
                 "template": coverage == "template", "tags": [], "coverage": coverage,
                 "ignore_reason": "", "ignored_by": "", "host": None}, **extra)


COVERAGE = {
    "proxmox": PM_OK,
    "summary": {"guests": 5, "managed": 1, "name_match": 1, "unmanaged": 1, "unmanaged_running": 1,
                "ignored": 1, "templates": 1, "stale_links": 1},
    "guests": [
        _guest(141, "web-prod-09", "unmanaged"),
        _guest(118, "api-gw-03", "name_match", host={"id": 7, "hostname": "api-gw-03.lab"}),
        _guest(190, "pfsense", "ignored", ignore_reason="Appliance, vendor-updated", ignored_by="lead1"),
        _guest(104, "web-prod-04", "managed", host={"id": 1, "hostname": "web-01"}),
        _guest(9000, "rocky9-tmpl", "template", status="stopped"),
    ],
    "stale_links": [{"host_id": 2, "hostname": "cache-07", "proxmox_vmid": 126, "proxmox_node": None}],
}


def _host_summary(**extra):
    return dict({"id": 1, "hostname": "web-01.lab", "team": "platform", "role": "web", "os_family": "rocky9",
                 "connectivity": "healthy", "status": "healthy", "pending_updates": 3,
                 "pending_by_severity": {"critical": 1, "moderate": 2}, "max_severity": "critical",
                 "updates_assessed_ok": True, "active_job_id": None, "last_seen": "2026-10-19T10:00:00",
                 "last_patched": None, "rollback_backend": "proxmox", "safety_net": "snapshot",
                 "containers": {"total": 2, "running": 2, "updatable": 1, "update_available": 1},
                 "placement": "live"}, **extra)


_SSH = {"proto": "tcp", "port": 22, "address": "0.0.0.0", "process": "sshd", "first_seen": "2026-10-19T10:00:00"}
_HTTPS = {"proto": "tcp", "port": 443, "address": "10.0.20.5", "process": "nginx", "first_seen": "2026-10-19T10:00:00"}


def _tm(guest, ips=(), ports=(), multi=False, nic="net0", bridge="vmbr20"):
    """A guest as it appears under one bridge: that NIC, its addresses and ports there."""
    return dict(guest, nic={"iface": nic, "mac": "bc:24:11:aa:bb:cc", "bridge": bridge, "firewall": False} if nic else None,
                ips=list(ips), ip_source="agent" if ips else "none", ports=list(ports), multi_homed=multi)


def _bsum(**kw):
    return dict({"machines": 1, "managed": 1, "unmanaged": 0, "listening": 0, "critical": 0, "active_runs": 0}, **kw)


_WEB = dict(_guest(104, "web-prod-04", "managed"), host=_host_summary(network_ok=True, default_gateway="10.0.20.254"),
            suggested_host=None)
_STRAY = dict(_guest(141, "web-prod-09", "unmanaged"), suggested_host=None)
_MATCH = dict(_guest(118, "api-gw-03", "name_match"), suggested_host={"id": 7, "hostname": "api-gw-03.lab"})
_DB = dict(_guest(207, "db-02", "managed", node="pve2", type_=None, status="unknown"),
           host=_host_summary(id=3, hostname="db-02", placement="pinned", safety_net="none", active_job_id=55),
           suggested_host=None)

TOPOLOGY = {
    "proxmox": PM_OK,
    "nodes": [
        {"name": "pve1", "status": "online", "maxcpu": 8, "maxmem": 1, "uptime": 1, "templates": 1,
         "template_list": [{"vmid": 9000, "name": "rocky9-tmpl", "type": "qemu"}],
         "guests": [_WEB, _STRAY, _MATCH],
         "networks": [
             {"key": "pve1/vmbr20", "kind": "vlan", "vlan_id": 20, "label": "VLAN 20 · vmbr20", "note": "",
              "bridges": ["pve1/vmbr20"], "subnets": ["10.0.20.0/24"],
              "summary": _bsum(machines=3, unmanaged=2, listening=2, critical=1),
              "members": [_tm(_WEB, ["10.0.20.5/24"], [_SSH, _HTTPS], multi=True), _tm(_STRAY), _tm(_MATCH)]},
             {"key": "pve1/vmbr1", "kind": "internal", "vlan_id": None, "label": "Servers · vmbr1",
              "note": "internal — no physical port", "bridges": ["pve1/vmbr1"], "subnets": ["10.0.1.0/24"],
              "summary": _bsum(listening=1, critical=1),
              "members": [_tm(_WEB, ["10.0.1.5/24"], [_SSH], multi=True, nic="net1", bridge="vmbr1")]},
         ],
         "blast_radius": {"guests": 3, "running": 3, "managed": 1, "unmanaged": 2, "active_runs": 0,
                          "no_snapshot": 0, "critical_pending": 1}},
        {"name": "pve2", "status": "unknown", "maxcpu": None, "maxmem": None, "uptime": None, "templates": 0,
         "template_list": [],
         "guests": [_DB],
         "networks": [
             {"key": "pve2/?", "kind": "unknown", "vlan_id": None, "label": "Network not read yet",
              "note": "this VM's NICs haven't been read from Proxmox", "bridges": [], "subnets": [],
              "summary": _bsum(critical=1, active_runs=1), "members": [_tm(_DB, nic=None)]},
         ],
         "blast_radius": {"guests": 1, "running": 0, "managed": 1, "unmanaged": 0, "active_runs": 1,
                          "no_snapshot": 1, "critical_pending": 1}},
    ],
    "unplaced": [_host_summary(id=4, hostname="bare-01", unplaced_reason="not_linked", proxmox_vmid=None,
                               placement="none", safety_net="package_history")],
}


def test_api_tokens_list_and_expired_row(js):
    html = _render(js, "renderSettings", {"user": ADMIN, "settingsTab": "tokens", "apiTokens": TOKENS,
                                          "apiTokensAll": True, "tokenCreated": None, "tokenRevoking": None})
    assert "desktop-assistant" in html and "kite_ab12" in html
    assert "Expired" in html and "Remove" in html
    assert "Owner" in html  # the All users column


def test_api_token_names_are_escaped(js):
    hostile = [dict(TOKENS[0], name='<img src=x onerror="alert(1)">')]
    html = _render(js, "renderSettings", {"user": ADMIN, "settingsTab": "tokens", "apiTokens": hostile,
                                          "tokenCreated": None, "tokenRevoking": None})
    assert "<img src=x" not in html


def test_token_created_dialog_shows_local_mcp_command(js):
    created = dict(TOKENS[0], token="kite_SECRETVALUE")
    html = _render(js, "renderSettings", {"user": OPERATOR, "apiTokens": [], "tokenCreated": created})
    assert "kite_SECRETVALUE" in html
    assert "won't be shown again" in html
    assert "/download/mcp-server" in html
    # the MCP client's server entry, filled in (HTML-escaped JSON)
    assert "&quot;KITE_URL&quot;: &quot;https://kite.example.com&quot;" in html
    assert "&quot;KITE_TOKEN&quot;: &quot;kite_SECRETVALUE&quot;" in html
    assert "&quot;command&quot;: &quot;python3&quot;" in html  # local stdio, not a remote endpoint


def test_revoke_confirm_is_inline(js):
    html = _render(js, "renderSettings", {"user": ADMIN, "settingsTab": "tokens", "apiTokens": TOKENS,
                                          "tokenCreated": None, "tokenRevoking": 1})
    assert "Revoke token" in html and "stops working immediately" in html


def test_coverage_renders_every_class_and_actions_by_role(js):
    base = {"fleetSection": "coverage", "coverage": COVERAGE, "coverageLoading": False,
            "coverageFilter": "all", "coverageShowTemplates": False, "coverageIgnoring": None, "fleet": HOSTS}
    admin = _render(js, "renderCoverage", dict(base, user=ADMIN))
    for word in ["Unmanaged", "Name match", "Ignored", "Managed", "Stale links", "cache-07"]:
        assert word in admin, word
    assert "Enroll" in admin and "Link" in admin and "Fix" in admin and "Ignore&hellip;" in admin
    assert "rocky9-tmpl" not in admin  # templates hidden by default
    lead = _render(js, "renderCoverage", dict(base, user={"username": "l", "role": "lead", "display_name": "L"}))
    assert "Ignore&hellip;" in lead and "Un-ignore" in lead
    assert ">Enroll<" not in lead and ">Fix<" not in lead and ">Link<" not in lead
    viewer = _render(js, "renderCoverage", dict(base, user=VIEWER))
    assert "Ignore&hellip;" not in viewer and "Un-ignore" not in viewer and ">Enroll<" not in viewer
    assert "Appliance, vendor-updated" in viewer  # the reason still shows


def test_coverage_status_states(js):
    base = {"user": ADMIN, "fleetSection": "coverage", "coverageIgnoring": None, "fleet": HOSTS,
            "coverageFilter": "all", "coverageShowTemplates": False}
    unconfigured = dict(COVERAGE, proxmox=dict(PM_OK, configured=False, error="not configured"))
    assert "Proxmox isn't connected" in _render(js, "renderCoverage", dict(base, coverage=unconfigured, coverageLoading=False))
    stale = dict(COVERAGE, proxmox=dict(PM_OK, error="401 Unauthorized", stale=True))
    html = _render(js, "renderCoverage", dict(base, coverage=stale, coverageLoading=False))
    assert "401 Unauthorized" in html and "last good fetch" in html and "web-prod-09" in html
    assert "Fetching from Proxmox" in _render(js, "renderCoverage", dict(base, coverage=COVERAGE, coverageLoading=True))


def test_ignore_dialog_and_hostile_guest_names(js):
    hostile = dict(COVERAGE, guests=[_guest(5, '<script>alert(1)</script>', "unmanaged")])
    html = _render(js, "renderCoverage", {"user": ADMIN, "fleetSection": "coverage", "coverage": hostile,
                                          "coverageLoading": False, "coverageFilter": "all", "fleet": HOSTS,
                                          "coverageIgnoring": {"vmid": 5, "name": '<script>alert(1)</script>'}})
    assert "<script>alert(1)</script>" not in html
    assert "Reason" in html and "Ignore guest" in html


def _topo(js, **patch):
    js.eval("state.topo = {k: 0.6, tx: 20, ty: 20, fitted: true, sel: null, colorBy: 'severity', filter: 'all', q: '', showTemplates: false, collapsed: {}};")
    return _render(js, "renderTopology", dict({"user": ADMIN, "topology": TOPOLOGY, "topologyLoading": False,
                                               "coverageIgnoring": None}, **patch))


def test_topology_draws_nodes_guests_and_unplaced(js):
    html = _topo(js)
    assert "pve1" in html and "pve2" in html and "Unplaced" in html
    assert "web-01" in html and "bare-01" in html and "web-prod-09" in html
    assert "Position from pinned node" in html  # pve2 is placed from pinned nodes
    assert "&#9650; 1 critical" in html
    assert "not linked to a VM id" in html
    assert "<svg" in html and "topo-flow" in html  # db-02's active run animates its edges


def test_topology_side_panel_for_a_host_and_a_gap(js):
    html = _topo(js)
    js.eval("state.topo.sel = 'host:1'")
    html = js.eval("renderTopology()")
    assert "Open machine" in html and "Snapshot before every patch" in html
    js.eval("state.topo.sel = 'vm:141'")
    html = js.eval("renderTopology()")
    assert "nobody is patching it" in html and ">Enroll<" in html


def test_topology_filters_dim_rather_than_hide(js):
    _topo(js)
    js.eval("state.topo.filter = 'gaps'")
    html = js.eval("renderTopology()")
    assert "web-01" in html and "dim" in html


def test_topology_templates_toggle(js):
    _topo(js)
    assert "rocky9-tmpl" not in js.eval("renderTopology()")
    js.eval("state.topo.showTemplates = true")
    assert "rocky9-tmpl" in js.eval("renderTopology()")


def test_viewer_sees_no_run_or_topology_actions(js):
    _topo(js, user=VIEWER)
    js.eval("state.topo.sel = 'vm:141'")
    html = js.eval("renderTopology()")
    assert ">Enroll<" not in html and "Ignore&hellip;" not in html


# ---------- Settings: Proxmox connection and rollback policy ----------

def _settings(js, tab, settings, **extra):
    return _render(js, "renderSettings", dict({"user": ADMIN, "settingsTab": tab, "settings": settings,
                                               "users": [], "checklistItems": [], "pmTest": None,
                                               "pmTesting": False, "pmForm": None, "pmConnections": [],
                                               "pmEditing": None, "pmRowTest": None}, **extra))


def test_connections_tab_shows_test_results(js):
    ok = {"ok": True, "nodes": 3, "guests": 41, "uses": [
        {"privilege": "VM.Audit", "use": "Coverage", "granted": True},
        {"privilege": "VM.Snapshot", "use": "snapshots", "granted": False}]}
    html = _settings(js, "connections", {}, pmTest=ok)
    assert "Connected." in html and "3 nodes, 41 guests" in html and "won" in html
    failed = _settings(js, "connections", {}, pmTest={"ok": False, "error": "<b>401</b>"})
    assert "Connection failed." in failed and "<b>401</b>" not in failed


def test_saved_values_are_escaped_in_the_form(js):
    html = _settings(js, "connections", {"rollback_proxmox_host": '"><script>x</script>'})
    assert "<script>x</script>" not in html


def test_proxmox_host_and_token_id_normalisation(js):
    assert js.eval("normalizeProxmoxHost(' https://pve1.lab:8006/#v1:0:18 ')") == "pve1.lab"
    assert js.eval("normalizeProxmoxHost('10.0.0.5')") == "10.0.0.5"
    assert js.eval("PROXMOX_TOKEN_ID_RE.test('kite@pve!kite')") is True
    assert js.eval("PROXMOX_TOKEN_ID_RE.test('kite@pve')") is False


def test_nodes_fan_out_into_bridges_and_vms_hang_off_them(js):
    html = _topo(js)
    assert "VLAN 20 · vmbr20" in html and "Servers · vmbr1" in html and "Network not read yet" in html
    assert "internal — no physical port" in html
    assert "10.0.20.5 &middot; 2 listening" in html and "10.0.1.5 &middot; 1 listening" in html
    assert html.count('title="web-prod-04"') == 2          # one tile under each bridge it's plugged into
    assert "&#8644;" in html                               # ...marked as on several bridges
    assert "Group by" not in html                          # one tree, no separate network mode


def test_selecting_a_vm_shows_each_bridge_with_its_ip_and_ports(js):
    _topo(js)
    js.eval("state.topo.sel = 'host:1'")
    html = js.eval("renderTopology()")
    assert "2 bridges" in html and html.count("topo-netblock") >= 2
    assert "tcp/22" in html and "tcp/443" in html and "nginx" in html
    assert "Gateway" in html and "10.0.20.254" in html and "Open machine" in html
    assert html.count('stroke="#1E6852"') >= 6              # both tiles' paths home light up


def test_selecting_a_bridge_lists_what_listens_on_it(js):
    _topo(js)
    js.eval("state.topo.sel = 'net:pve1/vmbr20'")
    html = js.eval("renderTopology()")
    assert "Listening on this bridge" in html and "10.0.20.0/24" in html and "pve1/vmbr20" in html


def test_collapsing_a_bridge_folds_only_that_bridge(js):
    _topo(js)
    js.eval("state.topo.collapsed = {'net:pve1/vmbr20': true}")
    html = js.eval("renderTopology()")
    assert 'title="web-prod-09"' not in html and html.count('title="web-prod-04"') == 1  # still under vmbr1
    assert "Expand 3" in html


def test_bridge_tree_escapes_agent_and_proxmox_text(js):
    evil = json.loads(json.dumps(TOPOLOGY))
    net = evil["nodes"][0]["networks"][0]
    net["label"] = '<img src=x onerror=alert(1)>'
    net["members"][0]["ports"] = [dict(_SSH, process='"><script>x</script>')]
    _topo(js, topology=evil)
    js.eval("state.topo.sel = 'host:1'")
    html = js.eval("renderTopology()")
    assert "<img src=x" not in html and "<script>x</script>" not in html


def test_bridge_tree_warns_when_vlans_are_unknown(js):
    unknown = json.loads(json.dumps(TOPOLOGY))
    unknown["nodes"][0]["networks"][1]["label"] = "vmbr1 · VLAN unknown"
    html = _topo(js, topology=unknown)
    assert "VLAN IDs unknown" in html and "SDN.Audit" in html
    assert "VLAN IDs unknown" not in _topo(js)


def test_an_unenrolled_vm_on_several_bridges_shows_the_marker(js):
    multi = json.loads(json.dumps(TOPOLOGY))
    multi["nodes"][0]["networks"][0]["members"][1]["multi_homed"] = True   # web-prod-09, unmanaged

    def tile_of(page, name):
        starts = [m.start() for m in re.finditer(r'<div class="topo-tile[ "]', page)]
        at = page.index(f'title="{name}"')
        start = max(x for x in starts if x < at)
        later = [x for x in starts if x > start]
        return page[start: later[0] if later else None]
    assert "&#8644;" in tile_of(_topo(js, topology=multi), "web-prod-09")
    assert "&#8644;" not in tile_of(_topo(js), "web-prod-09")


def _hostpage(js, net):
    host = dict(HOSTS[0])
    return _render(js, "renderHostDetail", {"user": ADMIN, "hostDetailId": 1, "hostDetail": {"host": host, "runs": []},
                                            "hostContainers": [], "hostUpdates": [], "hostNetwork": net,
                                            "hostShowContainerIfaces": False, "hostTab": "network", "hostPortsTable": True})


HOST_NET = {
    "ok": True, "error": "", "reported_at": "2026-10-19T10:00:00", "default_gateway": "10.0.20.254",
    "interfaces": [
        {"name": "eth0", "mac": "bc:24:11:aa:bb:cc", "kind": "", "up": True, "addresses": ["10.0.20.5/24"],
         "container": False, "proxmox": {"bridge": "vmbr20", "vlan_id": 20, "proxmox_iface": "net0", "firewall": False}},
        {"name": "docker0", "mac": "02:42:00:00:00:01", "kind": "bridge", "up": True, "addresses": ["172.17.0.1/16"],
         "container": True, "proxmox": None},
    ],
    "listening": [
        {"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd", "loopback": False,
         "first_seen": "2026-10-19T09:00:00", "last_seen": "2026-10-19T10:00:00"},
        {"proto": "tcp", "address": "127.0.0.1", "port": 5432, "process": "postgres", "loopback": True,
         "first_seen": "2026-10-19T09:00:00", "last_seen": "2026-10-19T10:00:00"},
    ],
}


def test_host_network_section(js):
    html = _hostpage(js, HOST_NET)
    assert "VLAN 20" in html and "10.0.20.5/24" in html and "every interface" in html and "sshd" in html
    assert "docker0" not in html and "Show 1 container interface" in html
    assert "1 more listening on loopback only" in html and "gateway 10.0.20.254" in html


def test_host_network_section_states(js):
    assert "Not reported" in _hostpage(js, dict(HOST_NET, ok=None, interfaces=[], listening=[]))
    assert "couldn't read the network" in _hostpage(js, dict(HOST_NET, ok=False, error="ss failed"))
    assert 'class="card-title" style="margin-top:22px">Network' not in _hostpage(js, None)


# ---------- Topology: containers under a VM ----------

TOPO_CONTAINERS = [
    {"id": 11, "name": "shop-web", "image": "docker.io/library/nginx:1.25", "state": "running", "managed_by": "compose",
     "compose_project": "shop", "compose_service": "web", "updatable": True, "rollback_available": True,
     "rollback_captured_at": "2026-10-18T10:00:00", "pinned": False, "update_available": True, "reported_at": "2026-10-19T10:00:00"},
    {"id": 12, "name": "shop-db", "image": "postgres@sha256:abc", "state": "running", "managed_by": "compose",
     "compose_project": "shop", "compose_service": "db", "updatable": True, "rollback_available": False,
     "rollback_captured_at": None, "pinned": True, "update_available": False, "reported_at": "2026-10-19T10:00:00"},
    {"id": 13, "name": "runner", "image": "gitlab/gitlab-runner:alpine", "state": "exited", "managed_by": "standalone",
     "compose_project": "", "compose_service": "", "updatable": False, "rollback_available": False,
     "rollback_captured_at": None, "pinned": False, "update_available": None, "reported_at": "2026-10-19T10:00:00"},
]


def _topo_expanded(js, containers, sel="host:1"):
    js.eval("state.topo = {k: 0.6, tx: 20, ty: 20, fitted: true, sel: null, colorBy: 'severity', filter: 'all', q: '', "
            "showTemplates: false, collapsed: {}, expanded: 1};")
    js.eval(f"state.topo.sel = {json.dumps(sel)}; state.topoContainers = {{1: {json.dumps(containers)}}};")
    return _render(js, "renderTopology", {"user": ADMIN, "topology": TOPOLOGY, "topologyLoading": False,
                                          "coverageIgnoring": None})


def test_selecting_a_vm_hangs_its_containers_off_it_as_a_chain(js):
    html = _topo_expanded(js, TOPO_CONTAINERS)
    assert 'title="containers on web-01.lab"' in html                # no runtime reported: generic
    js.eval("state.topology.nodes[0].guests[0].host.container_runtime = 'docker';"
            "state.topology.nodes[0].networks.forEach(n => n.members.forEach(m => { if(m.host && m.host.id === 1) m.host.container_runtime = 'docker'; }))")
    html = js.eval("renderTopology()")
    assert "topo-ctray" not in html                                  # no box any more
    assert 'class="topo-tile topo-rt' in html and 'title="docker on web-01.lab"' in html
    assert "shop-web" in html and "shop-db" in html and "runner" in html
    assert "shop &middot;" in html and "standalone &middot;" in html  # the project on each container
    assert ">NEW<" in html and ">PIN<" in html                        # outdated and pinned marked
    assert html.index("shop-web") < html.index("runner")              # compose first
    assert 'data-drag="ct:1:11"' in html and 'data-drag="rt:1"' in html


def test_the_chain_is_vm_then_runtime_then_containers(js):
    _topo_expanded(js, TOPO_CONTAINERS)
    L = json.loads(js.eval("(() => { const L = topoLayout(state.topology); return JSON.stringify({t: L.sub.target, rt: L.sub.rt, cts: L.sub.cts.map(c => ({x: c.x, y: c.y}))}); })()"))
    assert L["rt"]["y"] > L["t"]["y"] and all(c["y"] > L["rt"]["y"] for c in L["cts"])
    assert all(c["x"] > L["rt"]["x"] for c in L["cts"])               # indented under the runtime
    ys = [c["y"] for c in L["cts"]]
    assert ys == sorted(ys) and len(set(ys)) == len(ys)               # one per line


def test_runtime_panel_groups_by_project(js):
    html = _topo_expanded(js, TOPO_CONTAINERS, sel="rt:1")
    assert ">compose</span> <strong class=\"mono\">shop</strong>" in html
    assert "can’t update these safely" in html and "Open machine" in html


def test_chain_loading_and_error_states(js):
    assert "loading…" in _topo_expanded(js, None)
    assert "couldn't load: boom" in _topo_expanded(js, {"error": "boom"})


def test_the_chain_pushes_the_rows_below_it_down(js):
    _topo_expanded(js, TOPO_CONTAINERS)
    # api-gw-03 is the row below web-prod-04 under vmbr20; the first row stays put
    ys = "JSON.stringify(topoLayout(state.topology).items.filter(i => i.col === 'net:pve1/vmbr20').map(i => i.y))"
    expanded = json.loads(js.eval(ys))
    js.eval("state.topo.expanded = null")
    collapsed = json.loads(js.eval(ys))
    assert expanded[2] > collapsed[2] and expanded[0] == collapsed[0]


def test_selecting_a_container_shows_it_and_links_back_to_its_vm(js):
    html = _topo_expanded(js, TOPO_CONTAINERS, sel="ct:1:11")
    assert "docker.io/library/nginx:1.25" in html and "compose &middot; <span class=\"mono\">shop</span>" in html
    assert "Runs on" in html and "topoSelect('host:1')" in html
    assert "capture held" in html and "Containers</em> as the scope" in html
    assert "Open machine" in html


def test_container_names_and_images_in_the_chain_are_escaped(js):
    evil = [dict(TOPO_CONTAINERS[0], name='<img src=x onerror=alert(1)>', image='"><script>x</script>',
                 compose_project='<b>p</b>')]
    html = _topo_expanded(js, evil)
    assert "<img src=x" not in html and "<script>x</script>" not in html and "<b>p</b>" not in html


def test_an_outdated_container_counts_as_needing_action(js):
    js.eval("window.__h = {connectivity:'healthy', max_severity:'none', updates_assessed_ok:true, safety_net:'snapshot', containers:{total:1, update_available:1}}")
    assert js.eval("topoNeedsAction({coverage:'managed', host: window.__h})") is True
    js.eval("window.__h.containers.update_available = 0")
    assert js.eval("topoNeedsAction({coverage:'managed', host: window.__h})") is False


PM_CONNS = [
    {"id": 1, "name": "Main cluster", "host": "pve1.example.lan", "node": "", "token_id": "kite@pve!kite",
     "verify_ssl": False, "secret_set": True, "secret_from_env": False, "guests": 18, "linked_hosts": 4,
     "created_by": "admin", "created_at": "2026-10-19T10:00:00"},
    {"id": 2, "name": "Standalone", "host": "10.0.9.2", "node": "", "token_id": "kite@pve!kite",
     "verify_ssl": False, "secret_set": False, "secret_from_env": True, "guests": 1, "linked_hosts": 0,
     "created_by": "admin", "created_at": "2026-10-19T10:00:00"},
]


def test_connections_tab_lists_connections_and_offers_to_add_one(js):
    html = _settings(js, "connections", {}, pmConnections=PM_CONNS)
    assert "Main cluster" in html and "Standalone" in html and "pve1.example.lan" in html
    assert "2 connected" in html and "from .env" in html
    assert "18</span> VMs &middot; <span class=\"mono\">4</span> enrolled" in html
    assert "1</span> VM &middot;" in html                         # singular
    assert "Add connection" in html and "Create an API token on the Proxmox host" in html and "pveum user token add" in html
    # every privilege kite uses, so a fresh token can snapshot, restore and start the VM again
    assert 'VM.Audit Sys.Audit SDN.Audit VM.Snapshot VM.PowerMgmt' in html
    assert "rb-default" not in html                                # policy lives elsewhere
    empty = _settings(js, "connections", {}, pmConnections=[])
    assert "No connections yet" in empty and "None yet" in empty


def test_editing_fills_the_form_and_keeps_the_secret_blank(js):
    _settings(js, "connections", {}, pmConnections=PM_CONNS)
    js.eval("editProxmoxConnection(1)")
    html = js.eval("renderSettings()")
    assert 'value="Main cluster"' in html and 'value="pve1.example.lan"' in html
    assert "Saved — leave blank to keep it" in html and "Save changes" in html and "Cancel" in html
    js.eval("cancelProxmoxEdit()")
    html = js.eval("renderSettings()")
    assert 'value="Main cluster"' not in html and "Add connection" in html


def test_the_add_form_keeps_edits_across_rerenders(js):
    _settings(js, "connections", {}, pmConnections=PM_CONNS)
    js.eval("pmField('name', 'Lab'); pmField('host', 'https://typed.lab:8006/'); pmField('token_id', 'a@pve!b')")
    html = js.eval("renderSettings()")
    assert 'value="Lab"' in html and 'value="https://typed.lab:8006/"' in html
    assert js.eval("JSON.stringify(proxmoxFormValues())") == (
        '{"name":"Lab","host":"typed.lab","token_id":"a@pve!b","token_secret":"","node":"","verify_ssl":false}')
    assert js.eval("proxmoxFormError(proxmoxFormValues(), true)").startswith("Paste the token secret")
    js.eval("setSettingsTab('policy')")
    assert js.eval("state.pmForm") is None


def test_a_test_that_sees_another_connections_nodes_warns(js):
    ok = {"ok": True, "nodes": 1, "guests": 3, "uses": None, "overlaps": [{"connection": "Main cluster", "nodes": ["pve2"]}]}
    html = _settings(js, "connections", {}, pmConnections=PM_CONNS, pmTest=ok)
    assert "Already connected." in html and "Main cluster" in html and "show twice" in html


def test_connection_names_are_escaped(js):
    evil = [dict(PM_CONNS[0], name='<img src=x onerror=alert(1)>', host='"><script>x</script>')]
    html = _settings(js, "connections", {}, pmConnections=evil)
    assert "<img src=x" not in html and "<script>x</script>" not in html


def test_policy_tab_warns_only_when_there_is_no_connection(js):
    html = _settings(js, "policy", {"rollback_default_backend": "proxmox"}, pmConnections=[])
    assert "Rollback safety net" in html and 'name="rb-default"' in html
    assert "Proxmox isn't connected yet" in html
    assert "Proxmox isn't connected yet" not in _settings(js, "policy", {"rollback_default_backend": "proxmox"}, pmConnections=PM_CONNS)
    assert "Proxmox isn't connected yet" not in _settings(js, "policy", {"rollback_default_backend": "proxmox"}, pmConnections=None)
    assert "Proxmox isn't connected yet" not in _settings(js, "policy", {"rollback_default_backend": "none"}, pmConnections=[])


def test_topology_draws_one_cluster_box_per_connection(js):
    multi = json.loads(json.dumps(TOPOLOGY))
    multi["clusters"] = [{"connection_id": 1, "name": "Main cluster", "host": "pve1.example.lan", "error": "", "stale": False, "nodes": 1},
                         {"connection_id": 2, "name": "Standalone", "host": "10.0.9.2", "error": "401 Unauthorized", "stale": True, "nodes": 1}]
    multi["nodes"][0].update(key="1:pve", name="pve", connection_id=1, connection="Main cluster")
    multi["nodes"][1].update(key="2:pve", name="pve", connection_id=2, connection="Standalone")
    for n in multi["nodes"]:
        for net in n["networks"]:
            net["key"] = net["key"].replace("pve1/", "1:pve/").replace("pve2/", "2:pve/")
    html = _topo(js, topology=multi)
    assert html.count('class="topo-cluster') == 2 and "Main cluster" in html and "Standalone" in html
    assert "&#9650; error" in html                                 # the failing one is marked
    js.eval("state.topo.sel = 'node:2:pve'")
    assert "Standalone" in js.eval("renderTopology()")             # node panel names its connection
    js.eval("state.topo.sel = 'cluster:2'")
    panel = js.eval("renderTopology()")
    assert "401 Unauthorized" in panel and "last good fetch" in panel


# ---------- gateways ----------

_FW = dict(_guest(150, "edge-fw", "gateway"), suggested_host=None, connection_id=None)


def _with_gateway(source="tag"):
    """pve1 behind a firewall: vmbr0 uplink on top, the firewall under it, both zones below that."""
    topo = json.loads(json.dumps(TOPOLOGY))
    pve1 = topo["nodes"][0]
    vlan20, servers = pve1["networks"]
    uplink = {"key": "pve1/vmbr0", "kind": "bridge", "vlan_id": None, "label": "vmbr0", "note": "on eno1",
              "bridges": ["pve1/vmbr0"], "subnets": [], "depth": 0, "summary": _bsum(machines=0, managed=0),
              "members": []}
    for n in (vlan20, servers):
        n.update(depth=1, parent_gateway="pve1/gw:150")
    pve1["networks"] = [uplink, vlan20, servers]
    pve1["gateways"] = [dict(_FW, key="pve1/gw:150", source=source, depth=0, parent="pve1/vmbr0",
                             routed=["pve1/vmbr20", "pve1/vmbr1"], interfaces=[
                                 {"iface": "net0", "bridge": "vmbr0", "network": "pve1/vmbr0", "label": "vmbr0",
                                  "ips": [], "role": "uplink"},
                                 {"iface": "net1", "bridge": "vmbr20", "network": "pve1/vmbr20",
                                  "label": "VLAN 20 · vmbr20", "ips": ["10.0.20.1/24"], "role": "routes"},
                                 {"iface": "net2", "bridge": "vmbr1", "network": "pve1/vmbr1",
                                  "label": "Servers · vmbr1", "ips": [], "role": "routes"}])]
    return topo


def test_a_gateway_is_one_card_above_the_bridges_it_routes(js):
    html = _topo(js, topology=_with_gateway())
    assert html.count("topo-node topo-gw") == 1 and 'title="edge-fw"' in html
    assert "routes 2 bridges" in html and "uplink vmbr0" in html and "Proxmox tag" in html
    assert "net1 10.0.20.1/24" in html
    # the routed bridges sit a level lower than the uplink
    tops = {m.group(2): int(m.group(1)) for m in re.finditer(
        r'class="topo-node topo-bridge[^"]*"[^>]*top:(\d+)px[^>]*>\s*<div class="topo-node-head">\s*<span[^>]*></span>\s*<span class="topo-node-name">([^<]+)<', html)}
    assert tops["VLAN 20 · vmbr20"] > tops["vmbr0"]


def test_selecting_a_gateway_shows_its_interfaces_and_lights_its_path(js):
    _topo(js, topology=_with_gateway())
    js.eval("state.topo.sel = 'gw:pve1/gw:150'")
    html = js.eval("renderTopology()")
    assert "Routes the bridges below it" in html and "kite never touches this one" in html
    assert html.count("topo-netblock") == 3 and "routes" in html and "uplink" in html
    assert "remove the tag in Proxmox" in html and "Not a gateway" not in html     # tagged: undo it in Proxmox
    assert html.count('stroke="#1E6852" stroke-width="2.5"') >= 4                  # path home + both routed bridges
    _topo(js, topology=_with_gateway("marked"))
    js.eval("state.topo.sel = 'gw:pve1/gw:150'")
    assert "Not a gateway" in js.eval("renderTopology()")


def test_a_suggested_gateway_offers_promote_and_dismiss_to_leads_only(js):
    topo = json.loads(json.dumps(TOPOLOGY))
    topo["nodes"][0]["networks"][0]["members"][1]["gateway_suggestion"] = "the name looks like a router or firewall (fw)"
    html = _topo(js, topology=topo)
    assert 'title="Looks like a gateway: the name looks like a router' in html
    js.eval("state.topo.sel = 'vm:141'")
    html = js.eval("renderTopology()")
    assert "Looks like a gateway" in html and "Show as gateway" in html and "Not a gateway" in html
    assert "kite-gateway" in html
    _topo(js, topology=topo, user=VIEWER)
    js.eval("state.topo.sel = 'vm:141'")
    html = js.eval("renderTopology()")
    assert "Looks like a gateway" in html and "Show as gateway" not in html


def test_a_dismissed_suggestion_can_be_undone(js):
    topo = json.loads(json.dumps(TOPOLOGY))
    m = topo["nodes"][0]["networks"][0]["members"][1]
    m.update(gateway_suggestion="x", gateway_dismissed="lead1")
    html = _topo(js, topology=topo)
    assert 'title="Looks like a gateway' not in html
    js.eval("state.topo.sel = 'vm:141'")
    html = js.eval("renderTopology()")
    assert "Marked as not a gateway by lead1" in html and "Undo" in html


def test_gateway_names_are_escaped(js):
    topo = _with_gateway()
    topo["nodes"][0]["gateways"][0]["name"] = '<img src=x onerror=alert(1)>'
    topo["nodes"][0]["gateways"][0]["interfaces"][1]["label"] = '<script>x</script>'
    _topo(js, topology=topo)
    js.eval("state.topo.sel = 'gw:pve1/gw:150'")
    html = js.eval("renderTopology()")
    assert "<img src=x" not in html and "<script>x</script>" not in html


def test_coverage_lists_gateways_as_their_own_class(js):
    cov = json.loads(json.dumps(COVERAGE))
    cov["guests"].append(dict(_FW, gateway_source="marked"))
    cov["summary"]["gateways"] = 1
    html = _render(js, "renderCoverage", {"user": ADMIN, "fleetSection": "coverage", "coverage": cov,
                                          "coverageLoading": False, "coverageFilter": "all",
                                          "coverageShowTemplates": False, "coverageIgnoring": None, "fleet": HOSTS})
    assert "cov-gateway" in html and "patched outside kite" in html and "Not a gateway" in html
    assert "1 gateway patched elsewhere" in html


# ---------- moving cards, full screen ----------

def _positions(js):
    return json.loads(js.eval("(() => { const L = topoLayout(state.topology); return JSON.stringify({"
                              "node: L.nodePos['pve1'], net: L.byKey['net:pve1/vmbr20'], "
                              "tiles: L.items.filter(i => i.col === 'net:pve1/vmbr20').map(i => [i.key, i.x, i.y]), "
                              "other: L.byKey['net:pve1/vmbr1']}); })()"))


def test_moving_a_card_takes_everything_under_it_along(js):
    _topo(js)
    before = _positions(js)
    js.eval("state.topo.moved = {'net:pve1/vmbr20': [40, 120]}")
    after = _positions(js)
    assert after["net"]["x"] == before["net"]["x"] + 40 and after["net"]["y"] == before["net"]["y"] + 120
    for (k, x0, y0), (_, x1, y1) in zip(before["tiles"], after["tiles"]):
        assert (x1 - x0, y1 - y0) == (40, 120), k                   # its VMs came along
    assert after["other"]["x"] == before["other"]["x"]               # the sibling bridge didn't
    assert after["node"] == before["node"]                           # nor the node above


def test_moving_one_tile_moves_only_that_tile_and_its_edge_follows(js):
    _topo(js)
    before = _positions(js)
    key = before["tiles"][0][0]
    js.eval(f"state.topo.moved = {{{json.dumps(key)}: [0, 300]}}")
    after = _positions(js)
    assert after["tiles"][0][2] == before["tiles"][0][2] + 300 and after["tiles"][1] == before["tiles"][1]
    html = js.eval("renderTopology()")
    assert "Reset layout" in html and f'data-drag="{key}"' in html
    js.eval("state.topo.moved = {}")
    assert "Reset layout" not in js.eval("renderTopology()")


def test_moving_a_node_to_the_left_of_the_origin_still_fits(js):
    _topo(js)
    js.eval("state.topo.moved = {'node:pve1': [-2000, -50]}")
    L = json.loads(js.eval("(() => { const L = topoLayout(state.topology); return JSON.stringify({x0: L.x0, y0: L.y0}); })()"))
    assert L["x0"] < -1000 and L["y0"] < 0
    assert 'data-x0="' in js.eval("renderTopology()")


def test_every_card_can_be_dragged(js):
    html = _topo(js, topology=_with_gateway())
    for key in ['data-drag="root"', 'data-drag="cluster:0"', 'data-drag="node:pve1"', 'data-drag="net:pve1/vmbr20"',
                'data-drag="gw:pve1/gw:150"', 'data-drag="unplaced"', 'data-drag="t:net:pve1/vmbr20|host:1"']:
        assert key in html, key


def test_full_screen_toggle(js):
    html = _topo(js)
    assert "Full screen" in html and 'class="topo "' in html
    js.eval("state.topo.full = true")
    html = js.eval("renderTopology()")
    assert 'class="topo full"' in html and "Exit full screen" in html


def test_bridge_ports_are_folded_to_a_count_by_default(js):
    _topo(js)
    js.eval("state.topo.sel = 'net:pve1/vmbr20'")
    html = js.eval("renderTopology()")
    assert "Listening on this bridge" in html and "1 machine &middot; 2 ports" in html
    assert "tcp/443" not in html
    js.eval("state.topo.portsOpen = true")
    html = js.eval("renderTopology()")
    assert "tcp/443" in html and "topoSelect('host:1')" in html      # each machine links to its own panel


# ---------- where lines attach ----------

def _link(js, a, b):
    return json.loads(js.eval(f"JSON.stringify(topoLink({json.dumps(a)}, {json.dumps(b)}))"))


def test_lines_attach_to_the_facing_sides(js):
    _topo(js)
    a = {"x": 0, "y": 0, "w": 100, "h": 50}
    below = _link(js, a, {"x": 300, "y": 200, "w": 100, "h": 50})
    assert below["from"] == [50, 50] and below["d"].endswith("V200")          # bottom -> top
    above = _link(js, a, {"x": 0, "y": -200, "w": 100, "h": 50})
    assert above["from"] == [50, 0] and above["d"].endswith("V-150")          # top -> bottom
    right = _link(js, a, {"x": 300, "y": 10, "w": 100, "h": 50})
    assert right["from"] == [100, 25] and right["d"].endswith("H300")         # right side -> left side
    left = _link(js, a, {"x": -300, "y": 10, "w": 100, "h": 50})
    assert left["from"] == [0, 25] and left["d"].endswith("H-200")            # left side -> right side


def test_a_tile_moved_beside_its_bridge_gets_a_side_line(js):
    _topo(js)
    key = json.loads(js.eval("JSON.stringify(topoLayout(state.topology).items.filter(i => i.col === 'net:pve1/vmbr20').map(i => i.key))"))[0]
    spine = js.eval("topoCanvas(state.topology, topoLayout(state.topology))")
    # put it level with the bridge card, off to the right
    js.eval(f"(() => {{ const L = topoLayout(state.topology), c = L.byKey['net:pve1/vmbr20'], it = L.items.find(i => i.key === {json.dumps(key)});"
            f" state.topo.moved = {{{json.dumps(key)}: [c.x + 400 - it.x, c.y - it.y]}}; }})()")
    L = json.loads(js.eval("(() => { const L = topoLayout(state.topology), c = L.byKey['net:pve1/vmbr20']; return JSON.stringify({x: c.x, y: c.y}); })()"))
    moved = js.eval("topoCanvas(state.topology, topoLayout(state.topology))")
    right_edge = L["x"] + 160
    assert f'cx="{right_edge}" cy="{L["y"] + 56}"' in moved                   # leaves the bridge's right side
    assert moved != spine


# ---------- going back to a tab's own page ----------

def test_clicking_the_tab_you_are_on_goes_to_its_main_page(js):
    js.eval("state.user = {username:'a', role:'admin', display_name:'A'}; state.authChecked = true;"
            "state.nav = 'run'; state.run = Object.assign({}, state.run, {step: 2, jobId: 5, job: null, host: null});")
    js.eval("navClick('run')")
    assert js.eval("state.run.jobId") is None and js.eval("state.run.step") == 0
    assert js.eval("location.hash") == "run"
    # another tab remembers where you were...
    js.eval("state.fleetSection = 'coverage'; state.nav = 'topology'; navClick('fleet')")
    assert js.eval("state.nav") == "fleet" and js.eval("state.fleetSection") == "coverage"
    # ...until you click it again
    js.eval("navClick('fleet')")
    assert js.eval("state.fleetSection") == "hosts"
    # a machine page counts as Fleet
    js.eval("state.nav = 'host'; state.fleetSection = 'coverage'; navClick('fleet')")
    assert js.eval("state.nav") == "fleet" and js.eval("state.fleetSection") == "hosts"


def test_run_tab_home_lists_live_and_recent_runs(js):
    dash = {"active_runs": [{"job_id": 7, "hostname": "web-01", "stage": "patch", "stage_index": 3,
                             "total_stages": 7, "started_at": None}],
            "recent_runs": [{"job_id": 6, "hostname": "db-01", "status": "failed", "scope": "os",
                             "severity_filter": "", "operator": "a", "stage_index": 3}]}
    html = _render(js, "renderRun", {"user": ADMIN, "dashboard": dash,
                                     "run": {"step": 0, "host": None, "jobId": None, "job": None}})
    assert "Run patching" in html and "Choose a machine in Fleet" in html
    assert "openJobProgress(7)" in html and "Patch &middot; 4/7" in html
    assert "openJobProgress(6)" in html and ">failed<" in html


def test_a_run_page_links_back_to_the_tab(js):
    job = {"id": 9, "host_id": 1, "status": "running", "ticket_id": "", "stages": []}
    html = _render(js, "renderRun", {"user": ADMIN, "run": {"step": 2, "host": None, "jobId": 9, "job": job}})
    assert "navHome('run')" in html and "&larr; Run patching" in html


_UNINSTALLABLE = ("dnf stopped before installing anything: these updates can't be installed on this system.\n"
                  "[uninstallable] log-shipper 9.0.1-1 (from vendor-repo) needs libc.so.6(GLIBC_2.34)(64bit), which this system doesn't provide\n"
                  "Fix: add a 'skip' update rule for each package\n\nError: ...")


def _failed_run(js, user, defs=()):
    job = {"id": 9, "host_id": 1, "status": "failed", "ticket_id": "", "stages": [
        {"name": "patch", "status": "failed", "executor": "agent", "output": _UNINSTALLABLE}]}
    return _render(js, "renderRun", {"user": user, "fleet": HOSTS, "defs": list(defs),
                                     "run": {"step": 2, "host": None, "jobId": 9, "job": job}})


def test_an_uninstallable_update_is_explained_with_a_skip_rule_button(js):
    html = _failed_run(js, ADMIN)
    assert "Nothing was installed" in html and "log-shipper" in html and "from vendor-repo" in html
    assert "addSkipRuleFromRun('log-shipper','rocky9','vendor-repo')" in html and "Add skip rule for rocky9" in html
    assert "GLIBC_2.34" in html                                      # why, and the full output
    op = _failed_run(js, OPERATOR)
    assert "addSkipRuleFromRun" not in op and "Adding rules needs an admin" in op
    done = _failed_run(js, ADMIN, defs=[{"id": 1, "pkg_pattern": "log-shipper", "mode": "skip", "os_family": "rocky9"}])
    assert "skip rule exists" in done and "addSkipRuleFromRun" not in done


def test_skipped_updates_are_a_warning_on_a_finished_run(js):
    out = "Installed what could be installed. Skipped, left at the current version:\n[skipped] other-agent 3.0-1 (from vendor-repo)\n\nComplete!"
    job = {"id": 9, "host_id": 1, "status": "done", "ticket_id": "", "stages": [
        {"name": "patch", "status": "done", "executor": "agent", "output": out}]}
    html = _render(js, "renderRun", {"user": ADMIN, "fleet": HOSTS, "defs": [],
                                     "run": {"step": 2, "host": None, "jobId": 9, "job": job}})
    assert "these were skipped" in html and "other-agent" in html and "Run complete" in html


def test_policy_tab_has_the_skip_toggle(js):
    html = _settings(js, "policy", {"rollback_default_backend": "proxmox", "patch_skip_uninstallable": "true"}, pmConnections=[])
    assert "Skip updates that can't be installed" in html and "toggleSkipUninstallable(false)" in html


# ---------- agent updates from the console ----------

def _updates(**kw):
    rows = [{"host_id": 1, "hostname": "web-01", "agent_version": "0.1.8", "can_self_update": True, "behind": True, "updating_to": ""},
            {"host_id": 2, "hostname": "db-01", "agent_version": "0.1.8", "can_self_update": False, "behind": True, "updating_to": ""},
            {"host_id": 3, "hostname": "app-01", "agent_version": "0.1.10", "can_self_update": True, "behind": False, "updating_to": ""}]
    return dict({"published": ["0.1.10", "0.1.8"], "latest": "0.1.10", "fleet_target": "", "hosts": rows}, **kw)


def test_fleet_offers_to_update_agents_that_are_behind(js):
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": _updates()})
    assert "2 machines run an older agent" in html and "the newest is 0.1.10." in html
    assert "requestAgentUpdate('latest', null)" in html and ">Update it to 0.1.10<" in html     # only one can self-update
    assert "1 machine can’t update themselves" in html
    viewer = _render(js, "renderFleet", {"user": VIEWER, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": _updates()})
    assert "older agent" in viewer and "requestAgentUpdate" not in viewer


def test_fleet_shows_an_update_in_progress_and_can_stop_it(js):
    u = _updates(fleet_target="0.1.10")
    u["hosts"][0]["updating_to"] = "0.1.10"
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": u})
    assert "Updating 1 machine to 0.1.10" in html and "cancelAgentUpdate(null)" in html


def test_fleet_says_nothing_when_every_agent_is_current(js):
    u = _updates()
    u["hosts"] = [u["hosts"][2]]
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": u})
    assert "older agent" not in html and "requestAgentUpdate" not in html


def test_machine_page_can_update_just_this_agent(js):
    host = dict(HOSTS[0], agent_version="0.1.8")
    base = {"user": ADMIN, "hostDetailId": 1, "hostDetail": {"host": host, "runs": []}, "hostContainers": [],
            "hostUpdates": [], "hostNetwork": None, "hostShowContainerIfaces": False}
    html = _render(js, "renderHostDetail", dict(base, agentUpdates=_updates()))
    assert "requestAgentUpdate('0.1.10', 1)" in html and "Update to 0.1.10" in html
    u = _updates()
    u["hosts"][0]["updating_to"] = "0.1.10"
    html = _render(js, "renderHostDetail", dict(base, agentUpdates=u, hostDetail={"host": dict(host, agent_update_to="0.1.10"), "runs": []}))
    assert "updating to 0.1.10 on its next check-in" in html and "cancelAgentUpdate(1)" in html


def test_new_hosts_get_a_short_repo_metadata_expiry(js):
    # dnf would otherwise keep the repo's package list for 48h and miss a new agent
    cmd = js.eval("enrollCommand('rhel', {token: 'T'})")
    assert "metadata_expire=300" in cmd and "baseurl=" in cmd


# ---------- snapshot cleanup ----------

_SNAPS = {"policy": {"enabled": True, "keep_count": 2, "keep_days": 7}, "error": "", "snapshots": [
    {"name": "kite-job12-1", "job_id": 12, "job_status": "done", "kept": False, "taken_at": "2026-10-19T10:00:00", "remove": False, "reason": "recent"},
    {"name": "kite-job9-1", "job_id": 9, "job_status": "failed", "kept": False, "taken_at": "2026-10-10T10:00:00", "remove": False, "reason": "its run failed — the way back if needed"},
    {"name": "kite-job7-1", "job_id": 7, "job_status": "done", "kept": False, "taken_at": "2026-10-01T10:00:00", "remove": True, "reason": "older than 7 days"},
    {"name": "kite-job13-1", "job_id": 13, "job_status": "running", "kept": False, "taken_at": "2026-10-20T10:00:00", "remove": False, "reason": "its run is still going"},
]}


def _hostpage_snaps(js, user, snaps):
    return _render(js, "renderHostDetail", {"user": user, "hostDetailId": 1, "hostDetail": {"host": dict(HOSTS[0]), "runs": []},
                                            "hostContainers": [], "hostUpdates": [], "hostNetwork": None,
                                            "hostShowContainerIfaces": False, "hostSnapshots": snaps, "hostTab": "snapshots"})


def test_machine_page_lists_snapshots_and_what_cleanup_will_do(js):
    html = _hostpage_snaps(js, ADMIN, _SNAPS)
    assert "Keeps the newest 2, none older than 7 days" in html
    assert "removed at the next cleanup — older than 7 days" in html and "kept: its run failed" in html
    assert "keepSnapshot(1,'kite-job7-1',true)" in html and "deleteSnapshotNow(1,'kite-job7-1')" in html
    assert "deleteSnapshotNow(1,'kite-job13-1')" not in html          # its run is still going
    op = _hostpage_snaps(js, OPERATOR, _SNAPS)
    assert "kite-job7-1" in op and "keepSnapshot" not in op


def test_machine_page_snapshot_states(js):
    assert "Automatic cleanup is off" in _hostpage_snaps(js, ADMIN, dict(_SNAPS, policy={"enabled": False, "keep_count": 2, "keep_days": 7}))
    assert "No snapshots taken by kite" in _hostpage_snaps(js, ADMIN, dict(_SNAPS, snapshots=[]))
    assert "Couldn't read them: boom" in _hostpage_snaps(js, ADMIN, dict(_SNAPS, error="boom"))
    evil = dict(_SNAPS, snapshots=[dict(_SNAPS["snapshots"][0], name="<img src=x onerror=alert(1)>")])
    assert "<img src=x" not in _hostpage_snaps(js, ADMIN, evil)


def test_policy_tab_has_snapshot_cleanup_settings(js):
    html = _settings(js, "policy", {"rollback_default_backend": "proxmox", "snapshot_keep_count": "3", "snapshot_keep_days": "14"}, pmConnections=[])
    assert "Clean up old snapshots" in html and 'id="snap-keep-count"' in html and 'value="3"' in html and 'value="14"' in html
    off = _settings(js, "policy", {"rollback_default_backend": "proxmox", "snapshot_cleanup": "false"}, pmConnections=[])
    assert "setSnapshotSetting('snapshot_cleanup', 'true')" in off and 'id="snap-keep-count"' not in off


# ---------- apt's leftovers on a run ----------

def _apt_run(js, user, defs=()):
    out = ("Installed what apt would install. Not installed this run:\n"
           "[kept-back] kernel-meta needs a package added or removed, which `apt-get upgrade` never does\n"
           "[kept-back] extra-meta needs a package added or removed, which `apt-get upgrade` never does\n"
           "[phased] release-helper-core is being rolled out gradually by the distribution and will install on a later run\n\n...")
    job = {"id": 9, "host_id": 1, "status": "done", "ticket_id": "", "stages": [
        {"name": "patch", "status": "done", "executor": "agent", "output": out}]}
    fleet = [dict(HOSTS[0], os_family="ubuntu24")]
    return _render(js, "renderRun", {"user": user, "fleet": fleet, "defs": list(defs),
                                     "run": {"step": 2, "host": None, "jobId": 9, "job": job}})


def test_a_debian_run_lists_what_apt_kept_back_and_phased(js):
    html = _apt_run(js, ADMIN)
    assert "apt left 3 updates out of this run" in html
    assert "Kept back</strong> (2)" in html and "sudo apt-get install --only-upgrade kernel-meta extra-meta" in html
    assert "Phased</strong> (1)" in html and "Nothing to do" in html
    assert "addSkipRuleFromRun('kernel-meta','ubuntu24','','kept back by apt" in html
    assert "Run complete" in html                                   # still a successful run
    assert "addSkipRuleFromRun" not in _apt_run(js, OPERATOR)
    ruled = _apt_run(js, ADMIN, defs=[{"id": 1, "pkg_pattern": "kernel-meta", "mode": "skip", "os_family": ""}])
    assert "kernel-meta: skip rule exists" in ruled


def test_machine_page_offers_the_ubuntu_bundle_version(js):
    host = dict(HOSTS[0], agent_version="0.1.8", os_family="ubuntu24")
    u = {"published": ["0.1.12"], "bundle": "0.1.11", "latest": "0.1.12", "fleet_target": "",
         "hosts": [{"host_id": 1, "hostname": "web-01", "agent_version": "0.1.8", "latest": "0.1.11",
                    "can_self_update": True, "behind": True, "updating_to": ""}]}
    html = _render(js, "renderHostDetail", {"user": ADMIN, "hostDetailId": 1, "hostDetail": {"host": host, "runs": []},
                                            "hostContainers": [], "hostUpdates": [], "hostNetwork": None,
                                            "hostShowContainerIfaces": False, "agentUpdates": u})
    assert "requestAgentUpdate('0.1.11', 1)" in html                # what its channel actually has



def test_fleet_names_each_os_newest_and_updates_each_to_its_own(js):
    u = _updates(windows="0.5.0")
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": u})
    assert "the newest is 0.1.10 for Linux, 0.5.0 for Windows" in html
    u["hosts"][0]["updating_to"], u["hosts"][2]["updating_to"] = "0.1.10", "0.5.0"
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": u})
    assert "Updating 2 machines to 0.1.10 / 0.5.0" in html



def test_one_version_for_every_agent_is_shown_once(js):
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts",
                                       "agentUpdates": _updates(latest="0.6.0", windows="0.6.0")})
    assert "the newest is 0.6.0." in html and "for Windows" not in html


# ---------- removing hosts ----------

def _fleet_selected(js, hosts, user=ADMIN):
    js.eval(f"state.fleetSelected = new Set({json.dumps([h['id'] for h in hosts])});")
    return _render(js, "renderFleet", {"user": user, "fleet": hosts, "fleetSection": "hosts", "agentUpdates": None})


def test_any_host_can_be_removed_except_one_mid_run(js):
    live = dict(HOSTS[0], id=1, last_seen=datetime.utcnow().isoformat(), active_job_id=None)
    busy = dict(HOSTS[0], id=2, hostname="busy-01", last_seen=datetime.utcnow().isoformat(), active_job_id=9)
    html = _fleet_selected(js, [live, busy])
    assert ">Remove 1</button>" in html and "1 selected has a run in progress" in html
    assert "Remove 0" not in _fleet_selected(js, [live]) and ">Remove 1</button>" in _fleet_selected(js, [live])


def test_removing_a_host_that_is_still_checking_in_says_how_to_uninstall(js):
    now = datetime.utcnow().isoformat()
    hosts = [dict(HOSTS[0], id=1, hostname="rocky-01", os_family="rocky8", last_seen=now),
             dict(HOSTS[0], id=2, hostname="deb-01", os_family="ubuntu24", last_seen=now),
             dict(HOSTS[0], id=3, hostname="win-01", os_family="windows", last_seen=now),
             dict(HOSTS[0], id=4, hostname="gone-01", os_family="rocky9", last_seen="2026-01-01T00:00:00")]
    msg = js.eval(f"removeHostsMessage({json.dumps(hosts)})")
    assert msg.startswith("Remove 4 hosts from the fleet?") and "Past runs stay" in msg
    assert "rocky-01: sudo dnf remove kite-agent" in msg
    assert "deb-01: sudo systemctl disable --now kite-agent" in msg
    assert "win-01: kite-agent uninstall" in msg
    assert "gone-01:" not in msg                                     # offline: nothing to uninstall
    one = js.eval(f"removeHostsMessage({json.dumps(hosts[3:])})")
    assert one.startswith("Remove gone-01 from the fleet?") and "Still checking in" not in one


def test_machine_page_remove_is_enabled_unless_a_run_is_going(js):
    base = {"user": ADMIN, "hostDetailId": 1, "hostContainers": [], "hostUpdates": [], "hostNetwork": None,
            "hostShowContainerIfaces": False, "agentUpdates": None}
    live = dict(HOSTS[0], last_seen=datetime.utcnow().isoformat(), active_job_id=None)
    html = _render(js, "renderHostDetail", dict(base, hostDetail={"host": live, "runs": []}))
    assert 'onclick="deleteHost(1)">Remove from fleet' in html and "Remove this machine from kite" in html
    html = _render(js, "renderHostDetail", dict(base, hostDetail={"host": dict(live, active_job_id=4), "runs": []}))
    assert "It has a run in progress" in html


# ---------- patching several machines ----------

def _batch_wizard(js, rollout=None):
    hosts = [dict(HOSTS[0], id=1, hostname="web-01", pending_updates=3, max_severity="critical", safety_net="snapshot"),
             dict(HOSTS[0], id=2, hostname="web-02", pending_updates=0, safety_net="none", proxmox_vmid=None)]
    js.eval("state.user = {username:'op', role:'admin', display_name:'Op'}; state.authChecked = true;"
            f"state.fleet = {json.dumps(hosts)}; state.checklistItems = [{{id:1, text:'ok'}}];"
            "state.settings = {require_ticket:'false'}; startBatchRun([1, 2]);")
    js.eval(f"state.run.checklist = [true]; state.run.familyScripts = []; state.run.step = stepIndex('confirm');"
            f"state.run.rollout = {json.dumps(rollout)};")
    return js.eval("renderRun()")


def test_fleet_patches_several_selected_machines(js):
    js.eval("state.fleetSelected = new Set([1, 2]);")
    hosts = [dict(HOSTS[0], id=1), dict(HOSTS[0], id=2, hostname="web-02")]
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": hosts, "fleetSection": "hosts", "agentUpdates": None})
    assert "startBatchRun([1,2])" in html and "Patch 2 machines" in html
    assert "select a single machine" not in html                    # no longer one at a time only


def test_the_rollout_has_to_be_chosen_before_patching(js):
    html = _batch_wizard(js)
    assert "Run patch <span" in html and "2 machines" in html
    assert "One at a time" in html and "In parallel" in html
    assert "Choose how to roll out first" in html and "disabled onclick=\"confirmAndRun()\"" in html
    html = _batch_wizard(js, "one_at_a_time")
    assert "Choose how to roll out first" not in html and ">Patch 2 machines</button>" in html
    assert "web-01" in html and "web-02" in html and "No Proxmox VM ID on web-02" in html


def _batch_page(js, status="running", rollout="one_at_a_time", user=ADMIN, **extra):
    batch = dict({"id": 4, "rollout": rollout, "status": status, "paused_reason": "", "operator": "op",
                  "created_at": "2026-10-20T10:00:00", "finished_at": None, "settings": {},
                  "counts": {"done": 1, "failed": 0, "cancelled": 0, "running": 1, "queued": 0, "waiting": 1, "skipped": 0, "not started": 0},
                  "hosts": [{"host_id": 1, "hostname": "web-01", "state": "done", "job_id": 10, "stage": "", "stage_index": 7, "stage_count": 8, "skipped": "", "order": 1},
                            {"host_id": 2, "hostname": "web-02", "state": "running", "job_id": 11, "stage": "patch", "stage_index": 3, "stage_count": 8, "skipped": "", "order": 2},
                            {"host_id": 3, "hostname": "web-03", "state": "waiting", "job_id": None, "stage": "", "stage_index": 0, "stage_count": 0, "skipped": "", "order": 3}]}, **extra)
    return _render(js, "renderRun", {"user": user, "run": {"step": 0, "host": None, "batchId": 4, "batch": batch}})


def test_batch_page_shows_each_machine_and_where_it_is(js):
    html = _batch_page(js)
    assert "Batch 4" in html and "3 machines, one at a time" in html
    assert "openJobProgress(10)" in html and "openJobProgress(11)" in html and "Patch &middot; 4/8" in html
    assert ">waiting<" in html and "Stop after the current machine" in html


def test_a_paused_batch_asks_to_continue_or_stop(js):
    html = _batch_page(js, status="paused", paused_reason="web-02's run failed")
    assert "Paused: web-02&#39;s run failed" in html
    assert "batchAction('continue')" in html and "batchAction('stop')" in html
    assert "batchAction" not in _batch_page(js, status="paused", paused_reason="x", user=VIEWER)


def test_a_finished_batch_summarises(js):
    html = _batch_page(js, status="done", rollout="parallel",
                       counts={"done": 2, "failed": 1, "cancelled": 0, "running": 0, "queued": 0, "waiting": 0, "skipped": 0, "not started": 0})
    assert "Batch finished:</strong> 2 of 3 patched, 1 failed" in html and "Stop after" not in html


def test_starting_a_single_run_resets_the_scope_and_creating_a_ticket_no_longer_breaks(js):
    js.eval("state.runScope = 'containers'; state.runSeverity = 'critical'; state.fleet = [];"
            f"startRun(1, {json.dumps(dict(HOSTS[0], id=1))});")
    assert js.eval("state.runScope") == "os" and js.eval("state.runSeverity") == ""
    src = js.eval("createTicketHandler.toString()")
    assert "hostId" not in src                                     # the stray container load is gone


def test_a_batch_doesnt_claim_a_single_host_has_no_containers(js):
    html = _batch_wizard(js, "parallel")
    assert "No compose-managed containers on this host" not in html


# ---------- choosing your own password ----------

def test_a_temporary_password_shows_only_the_choose_password_step(js):
    js.eval("state.authChecked = true; state.user = {username:'sam', role:'operator', display_name:'Sam', must_change_password:true};"
            "state.choosePasswordError = ''; render();")
    view = js.eval("document.getElementById('view').innerHTML")
    assert "Choose your password" in view and "sam" in view and "Sign out instead" in view
    assert js.eval("document.getElementById('nav').innerHTML") == ""          # no way around it


def test_choosing_a_password_checks_the_basics_before_asking_the_server(js):
    js.eval("state.authChecked = true; state.user = {username:'sam', role:'operator', display_name:'Sam', must_change_password:true};")
    def attempt(cur, new, again):
        js.eval(f"document.getElementById('cp-current').value={json.dumps(cur)};"
                f"document.getElementById('cp-new').value={json.dumps(new)};"
                f"document.getElementById('cp-confirm').value={json.dumps(again)}; doChoosePassword();")
        return js.eval("state.choosePasswordError")
    assert "12 characters" in attempt("temp-password-1", "short", "short")
    assert "don’t match" in attempt("temp-password-1", "a-long-new-password", "a-long-new-passw0rd")
    assert "different" in attempt("same-long-password", "same-long-password", "same-long-password")


def test_the_reset_dialog_lets_the_admin_type_or_generate(js):
    users = [{"id": 2, "username": "sam", "display_name": "Sam", "role": "operator", "auth_source": "local", "must_change_password": True}]
    html = _settings(js, "access", {}, users=users, passwordResetDialog={"id": 2, "username": "sam"})
    assert "Reset sam's password" in html and "leave blank to generate one" in html
    assert "must choose a password" in html
    assert 'id="new-user-must-change" checked' in html


# ---------- a fleet list kept in the page ----------

def test_connectivity_is_judged_as_of_when_the_list_was_fetched(js):
    js.eval("window.__h = {last_seen: new Date(Date.now() - 2*3600*1000).toISOString().replace('Z',''), poll_interval_seconds: 900};")
    assert js.eval("connectivityTier(window.__h)") == "offline"                  # judged now: 2h of silence
    js.eval("window.__h._fetched_at = Date.now() - 2*3600*1000 + 60*1000;")     # fetched a minute after it checked in
    assert js.eval("connectivityTier(window.__h)") == "healthy"                  # it was fine then; the copy is just old


def test_opening_fleet_always_fetches_it_again(js):
    js.eval("state.user = {username:'a', role:'admin', display_name:'A'}; state.authChecked = true; state.fleet = [];"
            "window.__loads = 0; window.__realLoadFleet = loadFleet; loadFleet = function(){ window.__loads++; };"
            "state.nav = 'home'; navigate('fleet'); loadFleet = window.__realLoadFleet;")
    assert js.eval("window.__loads") == 1


def test_an_old_list_says_how_old_it_is(js):
    js.eval("state.fleetFetchedAt = Date.now() - 10*60*1000; state.fleetRefreshing = true;")
    html = _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": None})
    assert "Showing the fleet as of" in html and "updating…" in html
    js.eval("state.fleetFetchedAt = Date.now();")
    assert "Showing the fleet as of" not in _render(js, "renderFleet", {"user": ADMIN, "fleet": HOSTS, "fleetSection": "hosts", "agentUpdates": None})


# ---------- machine page: summary, tabs, compact ports ----------

def _machine(js, tab=None, **extra):
    updates = [{"package": f"pkg-{i}", "new_version": "2", "current_version": "", "severity": "critical" if i < 3 else "low",
                "is_security": True, "advisory": f"A-{i}", "source": "os"} for i in range(14)]
    net = json.loads(json.dumps(HOST_NET))
    net["listening"] = [{"proto": "tcp", "port": p, "address": a, "process": n, "loopback": False, "first_seen": "2026-10-19T10:00:00"}
                        for p, a, n in [(22, "0.0.0.0", "sshd"), (22, "::", "sshd"), (443, "0.0.0.0", "nginx"), (5432, "10.0.20.5", "postgres")]] + \
                       [{"proto": "tcp", "port": 6379, "address": "127.0.0.1", "process": "redis", "loopback": True, "first_seen": None}]
    base = {"user": ADMIN, "hostDetailId": 1, "hostDetail": {"host": dict(HOSTS[0], safety_net="snapshot"), "runs": [{"id": 3, "status": "done", "ticket_id": "", "operator": "a"}]},
            "hostContainers": [], "hostUpdates": updates, "hostNetwork": net, "hostShowContainerIfaces": False,
            "hostSnapshots": None, "hostPortsTable": False, "hostUpdatesAll": {}, "agentUpdates": None}
    if tab:
        base["hostTab"] = tab
    return _render(js, "renderHostDetail", dict(base, **extra))


def test_machine_page_has_a_summary_and_one_section_at_a_time(js):
    html = _machine(js, "updates")
    assert "14 pending" in html and "3 listening" in html and "Checked in" in html and "SNAP" in html
    assert "setHostTab('network')" in html and "setHostTab('runs')" in html
    assert "setHostTab('containers')" not in html.split("host-tabs")[1].split("</div>")[0]   # no containers, no tab
    assert "pkg-0" in html and "every interface" not in html                               # only the Updates tab's content
    assert html.count('class="panel-row"') <= 12 and "Show all 14" in html                 # ten most severe, then more


def test_ports_are_chips_per_address_with_the_table_a_click_away(js):
    html = _machine(js, "network")
    assert "every interface" in html and "tcp/22" in html and "tcp/443" in html
    assert html.count(">tcp/22 ") == 1                                                    # IPv4 and IPv6 shown once
    assert "10.0.20.5" in html and "+1 on loopback only" in html and ">Details</a>" in html
    table = _machine(js, "network", hostPortsTable=True)
    assert "First seen" in table and "Compact view" in table


def test_runs_have_their_own_tab(js):
    html = _machine(js, "runs")
    assert "openJobProgress(3)" in html and "pkg-0" not in html


def test_software_tab_lists_what_is_installed_and_searches_it(js):
    sw = {"reported_at": "2026-10-20T10:00:00", "items": [
        {"kind": "deb", "name": "libssl3t64", "version": "3.0.13-0ubuntu3.4", "arch": "amd64", "source_name": "openssl", "source_version": "", "publisher": ""},
        {"kind": "deb", "name": "bash", "version": "5.2.21", "arch": "amd64", "source_name": "bash", "source_version": "", "publisher": ""},
        {"kind": "snap", "name": "lxd", "version": "5.21.2", "arch": "", "source_name": "", "source_version": "", "publisher": "canonical"},
        {"kind": "os", "name": "ubuntu", "version": "24.04", "arch": "", "source_name": "", "source_version": "", "publisher": ""}]}
    html = _machine(js, "software", hostSoftware=sw, hostSoftwareQ="")
    assert "setHostTab('software')" in html and "4 installed" in html
    assert "Packages (deb)" in html and "Snap" in html and "openssl" in html and "canonical" in html
    found = _machine(js, "software", hostSoftware=sw, hostSoftwareQ="ssl")
    assert "1 match" in found and "libssl3t64" in found and ">bash<" not in found
    old = _machine(js, "software", hostSoftware={"reported_at": None, "items": []}, hostSoftwareQ="")
    assert "Not reported yet" in old


# ---------- vulnerabilities ----------

HOST_VULNS = {"covered": True, "feed": "Rocky Linux", "ecosystem": "Rocky Linux:9", "refreshed_at": "2026-10-21T01:00:00",
              "error": "", "matched_at": "2026-10-21T01:00:00",
              "counts": {"critical": 1, "important": 1, "moderate": 0, "low": 0, "unknown": 0, "none": 0, "total": 2},
              "items": [
                  {"cve": "CVE-2026-1001", "severity": "critical", "score": "9.8", "summary": "Critical: openssl security update",
                   "url": "https://errata.example/RLSA-1", "advisories": ["RLSA-1"],
                   "packages": [{"name": "openssl-libs", "installed": "1:3.0.7-25.el9", "fixed": "1:3.0.7-27.el9"}]},
                  {"cve": "CVE-2026-1002", "severity": "important", "score": "", "summary": "Important: curl",
                   "url": "", "advisories": ["RLSA-2"],
                   "packages": [{"name": "curl", "installed": "7.76.1-26.el9", "fixed": "7.76.1-29.el9"}]}]}


def test_vulnerabilities_tab_and_tile_on_the_machine_page(js):
    html = _machine(js, "vulns", hostVulns=HOST_VULNS, hostVulnsQ="")
    assert "setHostTab('vulns')" in html and "2 CVEs" in html
    assert "CVE-2026-1001" in html and "cve.org/CVERecord?id=CVE-2026-1001" in html
    assert "openssl-libs" in html and "1:3.0.7-27.el9" in html and "Rocky Linux:9" in html
    assert "patching this machine clears them" in html
    found = _machine(js, "vulns", hostVulns=HOST_VULNS, hostVulnsQ="curl")
    assert "1 match" in found and "CVE-2026-1001" not in found
    off = _machine(js, "vulns", hostVulns={"covered": False, "reason": "Vulnerability data is off — an admin can turn it on.",
                                           "counts": {"total": 0}, "items": []}, hostVulnsQ="")
    assert "Vulnerability data is off" in off and "not checked" in off


def test_fleet_vulnerabilities_search_and_filter(js):
    fleet = {"enabled": True, "total": 2, "items": [
        {"cve": "CVE-2026-1001", "severity": "critical", "score": "9.8", "summary": "openssl", "url": "", "host_count": 1,
         "hosts": [{"host_id": 7, "hostname": "web-01", "packages": [{"name": "openssl-libs", "installed": "1", "fixed": "2"}]}]},
        {"cve": "CVE-2026-1002", "severity": "moderate", "score": "", "summary": "curl", "url": "", "host_count": 1,
         "hosts": [{"host_id": 8, "hostname": "db-01", "packages": [{"name": "curl", "installed": "1", "fixed": "2"}]}]}]}
    base = {"user": VIEWER, "fleetSection": "vulns", "fleet": HOSTS, "vulns": fleet, "vulnsQ": "", "vulnsSeverity": ""}
    html = _render(js, "renderFleetVulns", base)
    assert "2 known vulnerabilities across 2 machines" in html and "openHostDetail(7)" in html and "web-01" in html
    assert "1 match" in _render(js, "renderFleetVulns", dict(base, vulnsQ="db-01"))
    only = _render(js, "renderFleetVulns", dict(base, vulnsSeverity="critical"))
    assert "CVE-2026-1001" in only and "CVE-2026-1002" not in only
    off = _render(js, "renderFleetVulns", dict(base, vulns={"enabled": False, "total": 0, "items": []}))
    assert "Vulnerability data is off" in off and "An admin can turn it on" in off
    assert _render(js, "renderFleetVulns", dict(base, vulns=None)).strip()


def test_vulnerability_settings_show_the_opt_in_and_each_source(js):
    status = {"enabled": True, "refreshing": False, "source": "https://osv.example", "feeds": [
        {"name": "Ubuntu", "needed": True, "ecosystems": ["Ubuntu:24.04:LTS"], "records": 13238,
         "refreshed_at": "2026-10-21T01:00:00", "error": ""},
        {"name": "Rocky Linux", "needed": True, "ecosystems": ["Rocky Linux:9"], "records": 0,
         "refreshed_at": None, "error": "no vulnerability data published at https://osv.example/x"}]}
    html = _render(js, "renderSettings", {"user": ADMIN, "settings": {"vuln_feed_enabled": "true"}, "users": [],
                                          "checklistItems": [], "settingsTab": "vulns", "vulnStatus": status})
    assert "Download vulnerability data" in html and "Enabled — click to disable" in html
    assert "Ubuntu:24.04:LTS" in html and "13238" in html and "Up to date" in html
    assert "Failed" in html and "Refresh now" in html and "nothing else about them is sent" in html
    off = _render(js, "renderSettings", {"user": ADMIN, "settings": {}, "users": [], "checklistItems": [],
                                         "settingsTab": "vulns", "vulnStatus": {"enabled": False, "feeds": []}})
    assert "Disabled — click to enable" in off and "Refresh now" not in off


def test_vendor_software_matches_are_labelled_with_their_source(js):
    hv = dict(HOST_VULNS, ecosystem=None, refreshed_at=None, third_party_refreshed_at="2026-10-21T01:00:00",
              os_note="The operating system itself isn't checked yet — RHEL, Rocky, AlmaLinux, Debian and Ubuntu are; Windows will follow.",
              items=[dict(HOST_VULNS["items"][0], source="nvd", packages=[{"name": "Google Chrome", "installed": "130.0.1", "fixed": "130.0.6723.91"}]),
                     dict(HOST_VULNS["items"][1], source="go")])
    html = _machine(js, "vulns", hostVulns=hv, hostVulnsQ="")
    assert ">NVD</span>" in html and ">GitHub</span>" in html and "Google Chrome" in html
    assert "vendor software via its own updates" in html and "Windows will follow" in html
    assert "OS: " not in html


def test_agent_updates_are_three_choices_not_a_version_to_type(js):
    base = {"user": ADMIN, "settingsTab": "policy", "users": [], "checklistItems": [], "agentUpdateMode": None,
            "agentUpdatePin": None, "agentUpdates": _updates(windows="0.1.10", bundle="0.1.10")}
    html = _render(js, "renderSettings", dict(base, settings={"agent_target_version": "latest"}))
    assert "Keep agents up to date" in html and "Update to a specific version" in html and "Don’t update agents" in html
    assert 'value="latest" checked' in html and "agent-target-version" not in html
    assert "2</strong> agents are behind" in html
    # pinned: the published versions to pick from, newest first
    html = _render(js, "renderSettings", dict(base, settings={"agent_target_version": "0.1.8"}))
    assert 'value="pin" checked' in html
    assert html.index('<option value="0.1.10"') < html.index('<option value="0.1.8" selected')
    html = _render(js, "renderSettings", dict(base, settings={"agent_target_version": ""}))
    assert 'value="off" checked' in html


def test_script_groups_list_their_machines_and_offer_the_rest(js):
    fleet = [dict(HOSTS[0], group_ids=[7]), dict(HOSTS[1], group_ids=[])]
    groups = [{"id": 7, "name": "db-servers", "description": "the databases", "host_ids": [1]},
              {"id": 8, "name": "empty-one", "description": "", "host_ids": []}]
    scripts = [{"os_family": "db-servers", "stage_name": "patch", "filename": "patch.sh", "tested": False,
                "uploaded_by": "admin", "uploaded_at": "2026-10-01T00:00:00"}]
    base = {"user": ADMIN, "osScripts": scripts, "fleet": fleet, "groups": groups, "groupEdit": None,
            "scriptsPick": [2], "scriptsPickQ": ""}
    html = _render(js, "renderScripts", dict(base, scriptsFamily="db-servers"))
    assert "OS families" in html and "Groups" in html and "Machines in this group" in html
    assert "+ New group" in html and "rename" in html and "delete group" in html and "the databases" in html
    members = html[html.index("Machines in this group"):html.index("Add machines")]
    assert "web-01" in members and "win-01" not in members
    assert "Add 1 machine" in html and "not set — each machine uses its OS family’s script" in html
    # a group with no scripts is still listed
    assert "empty-one" in html
    # an OS family isn't a group: no machine picker there
    html = _render(js, "renderScripts", dict(base, scriptsFamily="rocky9"))
    assert "Machines in this group" not in html and "1 of them in a group" in html
    html = _render(js, "renderScripts", dict(base, scriptsFamily="empty-one", groupEdit=8))
    assert "Rename group" in html


def test_machine_page_links_to_where_its_scripts_come_from(js):
    host = dict(HOSTS[0], group_ids=[7])
    groups = [{"id": 7, "name": "db-servers", "description": "", "host_ids": [1]},
              {"id": 8, "name": "pilot", "description": "", "host_ids": []}]
    js.eval(f"Object.assign(state, {json.dumps({'user': ADMIN, 'groups': groups})});")
    scripts = [{"os_family": "db-servers", "stage_name": "patch", "filename": "p.sh", "tested": True,
                "uploaded_by": "a", "uploaded_at": "2026-10-01T00:00:00"}]
    js.eval(f"state.hostDetail = {{host: {json.dumps(host)}, familyScripts: {json.dumps(scripts)}}};")
    card = js.eval(f"renderHostFamilyScripts({json.dumps(host)})")
    assert "openScriptsFor('db-servers')" in card and "Manage group db-servers" in card
    js.eval("state.hostDetail.familyScripts = [];")
    card = js.eval(f"renderHostFamilyScripts({json.dumps(dict(host, group_ids=[]))})")
    assert "openScriptsFor('rocky9')" in card
    admin = js.eval(f"renderHostAdminActions({json.dumps(host)}, true, true)")
    assert "db-servers" in admin and "Add to a group" in admin and '<option value="8">pilot</option>' in admin


def test_rules_show_and_pick_what_they_apply_to(js):
    fleet = [dict(HOSTS[0], group_ids=[7]), dict(HOSTS[1], group_ids=[])]
    groups = [{"id": 7, "name": "db-servers", "description": "", "host_ids": [1]}]
    defs = [{"id": 1, "pkg_pattern": "kernel*", "mode": "skip", "version": "", "reason": "r", "reviewed": "x", "targets": []},
            {"id": 2, "pkg_pattern": "postgres*", "mode": "skip", "version": "", "reason": "r", "reviewed": "x",
             "targets": [{"kind": "group", "value": "7"}, {"kind": "host", "value": "2"}, {"kind": "os", "value": "rocky9"}]}]
    base = {"user": ADMIN, "defs": defs, "fleet": fleet, "groups": groups, "defsSearch": "", "newRuleKeys": [],
            "newRule": {"pkg": "nginx", "mode": "skip", "version": "", "reason": "kept"}}
    html = _render(js, "renderDefs", dict(base, defTargets=None))
    assert "Every machine" in html and "db-servers" in html and "win-01" in html and ">OS</span>" in html
    assert 'value="nginx"' in html and 'value="kept"' in html            # the add form survives re-renders
    html = _render(js, "renderDefs", dict(base, defTargets={"id": 2, "keys": ["group:7"], "q": ""}))
    assert "toggleRuleTarget('group:7', this.checked)" in html and "OS families" in html and "Machines" in html
    assert js.eval("ruleApplies(state.defs[1], state.fleet[0])") is True       # in the group
    assert js.eval("ruleApplies(state.defs[1], {id: 9, os_family: 'ubuntu24', group_ids: []})") is False
    assert js.eval("ruleApplies(state.defs[0], {id: 9, os_family: 'ubuntu24', group_ids: []})") is True


# ---------- a large fleet: long lists are paged, capped or scroll ----------

def test_a_big_batch_filters_by_state_and_shows_thirty_at_a_time(js):
    hosts = [{"host_id": i, "hostname": f"m-{i:03d}", "state": "failed" if i == 77 else "done" if i < 60 else "waiting",
              "job_id": i if i < 78 else None, "stage": "", "stage_index": 0, "stage_count": 8, "skipped": "", "order": i}
             for i in range(1, 121)]
    js.eval("state.batchFilter = 'all'; state.batchShowAll = false;")
    html = _batch_page(js, hosts=hosts)
    assert "Failed / stopped / skipped" in html and "m-030" in html and "m-031" not in html and "Show all 120" in html
    js.eval("state.batchFilter = 'problem';")
    html = _batch_page(js, hosts=hosts)
    assert "m-077" in html and "m-001" not in html
    js.eval("state.batchFilter = 'all';")
    assert "Failed / stopped" not in _batch_page(js)                    # a small batch needs none of it


def test_long_rule_targets_are_capped(js):
    fleet = [dict(HOSTS[0], id=i, hostname=f"machine-{i:03d}", group_ids=[]) for i in range(1, 15)]
    targets = [{"kind": "host", "value": str(i)} for i in range(1, 13)]
    defs = [{"id": i, "pkg_pattern": f"pkg-{i:02d}", "mode": "pin", "version": "1.2.3-4.el9_5.very.long", "reason": "r",
             "reviewed": "x", "targets": targets if i == 1 else []} for i in range(1, 31)]
    base = {"user": ADMIN, "defs": defs, "fleet": fleet, "groups": [], "defsSearch": "", "defTargets": None,
            "defsTargetsOpen": {}, "defsPage": 0}
    html = _render(js, "renderDefs", base)
    assert "+9 more" in html and "machine-004" not in html
    assert "1–25 of 30" in html and "pkg-26" not in html
    assert "machine-012" in _render(js, "renderDefs", dict(base, defsTargetsOpen={"1": True}))
    assert "pkg-26" in _render(js, "renderDefs", dict(base, defsPage=1))


def test_a_cve_on_many_machines_lists_five(js):
    hosts = [{"host_id": i, "hostname": f"m-{i:03d}", "packages": [{"name": "curl", "installed": "1", "fixed": "2"}]} for i in range(40)]
    items = [{"cve": f"CVE-2026-{i:04d}", "severity": "moderate", "score": "", "summary": "s", "url": "", "host_count": 40,
              "hosts": hosts} for i in range(60)]
    base = {"user": VIEWER, "fleetSection": "vulns", "fleet": HOSTS, "vulnsQ": "", "vulnsSeverity": "", "vulnsPage": 0,
            "vulnsHostsOpen": {}, "vulns": {"enabled": True, "total": 60, "items": items}}
    html = _render(js, "renderFleetVulns", base)
    assert "+35 more machines" in html and "m-005" not in html and "1–50 of 60" in html


def test_run_home_lists_ten_runs_in_progress(js):
    active = [{"job_id": i, "hostname": f"m-{i}", "stage": "patch", "stage_index": 3, "total_stages": 8} for i in range(40)]
    html = _render(js, "renderRunHome", {"user": ADMIN, "dashboard": {"active_runs": active, "recent_runs": []},
                                         "runHomeAllActive": False, "batchesRecent": []})
    assert "Show all 40" in html and "openJobProgress(9)" in html and "openJobProgress(10)" not in html


def test_scripts_page_searches_its_lists(js):
    groups = [{"id": i, "name": f"team-{i:02d}", "description": "", "host_ids": []} for i in range(20)]
    html = _render(js, "renderScripts", {"user": ADMIN, "osScripts": [], "fleet": HOSTS, "groups": groups, "groupEdit": None,
                                         "scriptsFamily": "team-00", "scriptsListQ": "team-1", "scriptsPick": [], "scriptsPickQ": "",
                                         "scriptsMemberQ": ""})
    assert "Find a family or group" in html and "team-15" in html and "team-05" not in html
    assert "team-00" in html                                            # the selected one stays listed


# ---------- restoring a snapshot; the safety net ----------

def test_snapshots_offer_restore_to_admins_only(js):
    html = _hostpage_snaps(js, ADMIN, _SNAPS)
    assert "restoreSnapshot(1,'kite-job9-1')" in html and "everything written since is lost" in html
    assert "restoreSnapshot(1,'kite-job13-1')" not in html            # its run is still going
    assert "restoreSnapshot" not in _hostpage_snaps(js, {"username": "l", "role": "lead", "display_name": "L"}, _SNAPS)


def test_a_finished_run_offers_its_snapshot_back(js):
    snap = {"name": "snapshot", "status": "done", "executor": "controller",
            "output": "Snapshot 'kite-job9-1700000000' created for VM 4321 on node pve (backend: proxmox)"}
    for status in ("failed", "done"):
        job = {"id": 9, "host_id": 1, "status": status, "ticket_id": "", "stages": [snap]}
        html = _render(js, "renderRun", {"user": ADMIN, "fleet": HOSTS, "defs": [], "run": {"step": 2, "host": None, "jobId": 9, "job": job}})
        assert "restoreSnapshot(1, 'kite-job9-1700000000')" in html
    viewer = _render(js, "renderRun", {"user": OPERATOR, "fleet": HOSTS, "defs": [], "run": {"step": 2, "host": None, "jobId": 9, "job": job}})
    assert "restoreSnapshot" not in viewer
    nosnap = dict(job, stages=[])
    assert "restoreSnapshot" not in _render(js, "renderRun", {"user": ADMIN, "fleet": HOSTS, "defs": [], "run": {"step": 2, "host": None, "jobId": 9, "job": nosnap}})


def test_the_safety_net_tile_reads_the_host(js):
    assert ">SNAP<" in _machine(js) and "snapshot before each run" in _machine(js)
    none = _machine(js, hostDetail={"host": dict(HOSTS[0], safety_net="none"), "runs": []})
    assert ">NONE<" in none and "no rollback" in none


def test_a_typed_confirmation_keeps_the_button_off_until_it_matches(js):
    js.eval("confirmDialog({title: 'Restore', message: 'm', danger: true, typeToConfirm: 'web-01'});")
    html = js.eval("document.getElementById('modal-root').innerHTML")
    assert 'id="confirm-typed"' in html and 'id="confirm-go" disabled' in html and "web-01" in html
    js.eval("window.__closeConfirm(false)")


def test_settings_lists_database_backups(js):
    backups = {"keep": 7, "dir": "/var/lib/kite/backups", "backups": [
        {"name": "kite-20261026-010000.db.gz", "size_bytes": 4200000, "taken_at": "2026-10-26T01:00:00"}]}
    base = {"user": ADMIN, "settingsTab": "policy", "users": [], "checklistItems": [], "settings": {}, "agentUpdates": None}
    html = _render(js, "renderSettings", dict(base, dbBackups=backups))
    assert "Database backups" in html and "Back up now" in html and "4.0 MB" in html
    assert 'href="/backups/kite-20261026-010000.db.gz"' in html and 'id="db-backup-keep"' in html
    assert "No backup yet" in _render(js, "renderSettings", dict(base, dbBackups=dict(backups, backups=[])))


def test_the_maintenance_window_is_judged_in_utc_like_the_server(js):
    """The server checks the window in UTC; a browser twelve hours away from
    UTC must reach the same answer, not its own local-time one."""
    js.eval("Date.prototype.__getHours = Date.prototype.getHours;"
            "Date.prototype.getHours = function(){ return (this.getUTCHours() + 12) % 24; }")
    try:
        hour = js.eval("new Date().getUTCHours()")
        ticket = {"ticket_id": "CHG-1", "status": "Approved", "description": "", "requester": "a",
                  "window_start": hour, "window_end": hour}
        html = _render(js, "renderTicketResult", {"user": ADMIN, "run": {"ticketInfo": ticket}})
        assert "Outside approved maintenance window" not in html and "UTC" in html
        ticket = dict(ticket, window_start=(hour + 12) % 24, window_end=(hour + 12) % 24)
        html = _render(js, "renderTicketResult", {"user": ADMIN, "run": {"ticketInfo": ticket}})
        assert "Outside approved maintenance window" in html
    finally:
        js.eval("Date.prototype.getHours = Date.prototype.__getHours;")


def test_container_rollback_sends_the_ticket(js):
    """Without it, a rollback failed whenever runs need a ticket."""
    sent = json.loads(js.eval(
        "var __sent; var __apiCall = apiCall;"
        "apiCall = function(m, p, b){ __sent = b; return Promise.resolve({}); };"
        "api.rollbackContainer(1, 'web', {ticket_id: 'CHG-1', window_override_reason: null});"
        "apiCall = __apiCall; JSON.stringify(__sent)"))
    assert sent["ticket_id"] == "CHG-1" and sent["container_action"] == "rollback" and sent["containers"] == ["web"]


@pytest.mark.parametrize("backend, vmid, says, fails", [
    ("proxmox", 101, "Proxmox snapshot of VM 101", False),
    ("proxmox", None, "no VM ID set", True),
    ("dnf_history", None, "Package history", False),
    ("none", None, "without a safety net", False),
])
def test_the_confirm_page_names_the_hosts_real_rollback_method(js, backend, vmid, says, fails):
    """It said 'Proxmox' for every host, whatever its rollback backend."""
    js.eval(f"Object.assign(state, {json.dumps({'settings': {'rollback_default_backend': 'proxmox'}})});")
    got = json.loads(js.eval(
        f"JSON.stringify(snapshotMethod({json.dumps({'rollback_backend': backend, 'proxmox_vmid': vmid})}))"))
    assert says in got["text"] and got["fails"] is fails
    # no override on the host: the Settings default decides
    js.eval(f"Object.assign(state, {json.dumps({'settings': {'rollback_default_backend': backend}})});")
    assert json.loads(js.eval(
        f"JSON.stringify(snapshotMethod({json.dumps({'rollback_backend': None, 'proxmox_vmid': vmid})}))"))["fails"] is fails


def test_an_operator_can_patch_selected_machines_but_not_remove_them(js):
    js.eval(f"Object.assign(state, {json.dumps({'user': OPERATOR, 'fleet': HOSTS})});"
            f"state.fleetSelected = new Set([{HOSTS[0]['id']}]);")
    try:
        html = js.eval("renderFleet()")
    finally:
        js.eval("state.fleetSelected = new Set();")
    assert ">Patch<" in html and "Remove 1" not in html and "Add machine" not in html


def test_new_ticket_is_offered_only_to_roles_that_may_create_one(js):
    run = {"step": 0, "ticketId": "", "ticketInfo": None, "ticketError": "", "host": HOSTS[0]}
    for user, shown in ((OPERATOR, False), ({"username": "tl", "role": "lead", "display_name": "TL"}, True)):
        html = _render(js, "renderStepTicket", {"user": user, "run": run, "showNewTicketForm": False})
        assert ("+ New ticket" in html) is shown


def test_an_expired_session_stops_polling(js):
    """Each poll's 401 re-rendered the login page, wiping what was being typed."""
    js.eval("state.run = Object.assign({}, state.run, {pollHandle: 7}); state.addMachine = {pollHandle: 8};"
            "var __cleared = []; var __ci = clearInterval; clearInterval = function(h){ __cleared.push(h); };")
    try:
        js.eval("stopPolls()")
        assert json.loads(js.eval("JSON.stringify(__cleared)")) == [7, 8]
        assert js.eval("state.run.pollHandle === null && state.addMachine.pollHandle === null")
    finally:
        js.eval("clearInterval = __ci; state.addMachine = null;")


def _enrol(js, platform, ca):
    js.eval("window.location = {protocol: 'https:', host: 'kite.example'};")
    js.eval(f"state.agentDownloads = [{{platform: 'rhel', signed: true}}]; state.controllerCa = {json.dumps(ca)};")
    try:
        return js.eval(f"enrollCommand('{platform}', {{token: 'TOK'}})")
    finally:
        js.eval("state.controllerCa = null;")


def test_enrol_commands_check_the_controllers_ca_when_it_has_one(js):
    fp = "ab" * 32
    ca = {"available": True, "sha256": fp}
    for platform in ("rhel", "debian"):
        cmd = _enrol(js, platform, ca)
        assert f'= "{fp}"' in cmd and "/download/ca.crt" in cmd
        assert "insecure" not in cmd.lower() and "sslverify=0" not in cmd and "curl -fsSLk" not in cmd
        # every step after the check depends on it
        before, after = cmd.split(f'= "{fp}"', 1)
        assert after.startswith(" && \\\n")
    assert "sslverify=1\nsslcacert=/etc/kite/controller-ca.crt" in _enrol(js, "rhel", ca)
    assert "KITE_CA_CERT=/etc/kite/controller-ca.crt" in _enrol(js, "rhel", ca)
    assert "--ca-cert /tmp/kite-ca.crt" in _enrol(js, "debian", ca)
    win = _enrol(js, "windows", ca)
    assert f"/ca-fingerprint={fp}" in win and "/insecure" not in win


def test_without_a_ca_enrol_commands_are_as_before(js):
    none = {"available": False, "sha256": ""}
    assert "KITE_INSECURE=1" in _enrol(js, "rhel", none) and "sslverify=0" in _enrol(js, "rhel", none)
    assert "--insecure" in _enrol(js, "debian", none)
    assert "/insecure" in _enrol(js, "windows", none)


def test_the_proxmox_bar_says_when_a_newer_list_is_on_its_way(js):
    ok = {"configured": True, "host": "pve.lab", "nodes": 2, "error": "", "stale": False,
          "fetched_at": "2026-09-05T11:58:00", "refreshing": True, "retry_in": None}
    js.eval(f"Object.assign(state, {json.dumps({'user': ADMIN})});")
    assert "updating…" in js.eval(f"proxmoxStatusBar({json.dumps(ok)}, false, 'x()')")
    down = dict(ok, error="Proxmox didn't answer in time.", stale=True, refreshing=False, retry_in=170)
    html = js.eval(f"proxmoxStatusBar({json.dumps(down)}, false, 'x()')")
    assert "Tries again in about 3 min" in html and "answer in time." in html
    assert "Trying again now" in js.eval(f"proxmoxStatusBar({json.dumps(dict(down, refreshing=True))}, false, 'x()')")


def test_a_viewer_isnt_offered_tabs_it_cant_load(js):
    """Network, software and snapshots are operator+; a viewer saw them stuck on Loading."""
    host = dict(HOSTS[0], proxmox_vmid=101)
    js.eval(f"Object.assign(state, {json.dumps({'user': VIEWER, 'hostContainers': []})});")
    shown = json.loads(js.eval(f"JSON.stringify(hostTabsShown({json.dumps(host)}).map(t => t.id))"))
    assert not {"network", "software", "snapshots"} & set(shown) and "updates" in shown
    js.eval(f"Object.assign(state, {json.dumps({'user': OPERATOR})});")
    shown = json.loads(js.eval(f"JSON.stringify(hostTabsShown({json.dumps(host)}).map(t => t.id))"))
    assert {"network", "software", "snapshots"} <= set(shown)


def test_the_checklist_step_says_when_it_failed_or_there_is_none(js):
    base = {"user": OPERATOR, "run": {"step": 1, "checklist": [], "host": HOSTS[0]}}
    assert "Loading checklist" in _render(js, "renderStepChecklist", dict(base, checklistItems=None, checklistError=""))
    html = _render(js, "renderStepChecklist", dict(base, checklistItems=None, checklistError="timed out"))
    assert "Couldn't load the checklist" in html and "Try again" in html
    html = _render(js, "renderStepChecklist", dict(base, checklistItems=[], checklistError=""))
    assert "No pre-run checklist is set up" in html and "Continue" in html
    html = _render(js, "renderStepChecklist", dict(base, checklistError="",
                                                   checklistItems=[{"id": 1, "text": "Backups verified"}]))
    assert "Backups verified" in html and "valid until" not in html     # no made-up lead review


def test_csv_export_cells_cant_be_formulas(js):
    row = dict(HOSTS[0], os_version="=HYPERLINK(\"http://x\")", team="-2+3", role="@SUM(A1)")
    js.eval(f"Object.assign(state, {json.dumps({'user': ADMIN, 'fleet': [row]})});")
    js.eval("var __blob; Blob = function(parts){ __blob = parts.join(''); };"
            "URL = {createObjectURL: function(){ return 'x'; }, revokeObjectURL: function(){}};")
    js.eval("try{ fleetExportCsv(); }catch(e){}   // the stub DOM has no click(); the file is built before it")
    line = js.eval("__blob").split("\n")[1]
    assert "'=HYPERLINK" in line and ",'-2+3," in line and ",'@SUM(A1)," in line


def test_back_and_forward_follow_the_hash_but_app_navigation_doesnt_double_load(js):
    js.eval("setHash('fleet')")
    assert js.eval("location.hash") == "fleet" and js.eval("state.__routedHash") == "#fleet"
