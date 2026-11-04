"""
Which CVEs each host is exposed to: its installed packages (agent
software inventory, app/routers/agent.py) matched against the
distributions' own security data, as OSV publishes it
(https://osv.dev, served from a public Google Cloud Storage bucket).

Off until an admin turns it on (Settings -> Vulnerabilities): it is the
one feature that makes the controller download from the internet. Only
the bulk files are fetched -- nothing about the fleet is sent anywhere,
not even package names -- and only for the OS releases the fleet runs:

  RHEL family   "Rocky Linux", "AlmaLinux", "Red Hat"   5-30 MB
  Debian        "Debian"                               ~80 MB
  Ubuntu        "Ubuntu"                               ~800 MB

Always the whole ecosystem: OSV's per-release files ("Ubuntu:24.04:LTS")
stopped being updated in 2024. Only the releases the fleet runs are kept
from it. The first download is the whole file; after that, each day's
refresh reads the ecosystem's modified_id.csv and fetches only the
records that changed. A full download is repeated every FULL_RELOAD_DAYS,
or when a host on a new release appears.

Only records that name a fixed version are kept: a match means "an
update fixes this" -- what a patch run can act on. A host is matched
after each software report and after every refresh. Windows itself is
matched against Microsoft's Security Update Guide (app/windows_os.py),
software from vendors' own repositories against GitHub and NVD
(app/third_party.py).
"""
import asyncio
import csv
import io
import json
import os
import re
import shutil
import threading
import zipfile
from datetime import datetime, timedelta

import requests
from sqlalchemy.orm import Session

from . import friendly_errors, models, third_party, windows_os
from .config import STATE_DIR
from .db import SessionLocal
from .logging_config import logger
from .settings_store import get_setting
from .versioncmp import cvss3_base_score, dpkg_compare, rpm_compare, severity_from_score

BASE_URL = os.environ.get("KITE_OSV_URL", "https://osv-vulnerabilities.storage.googleapis.com").rstrip("/")
FULL_RELOAD_DAYS = 90
MAX_INCREMENTAL = 3000          # more changed records than this: download the whole file instead
STARTUP_DELAY_SECONDS = 300
PASS_SECONDS = 24 * 3600
TIMEOUT = 60
_lock = threading.Lock()        # one refresh at a time (the daily loop or the Refresh button)

_SEVERITY_WORDS = {
    "critical": "critical", "important": "important", "high": "important",
    "moderate": "moderate", "medium": "moderate", "low": "low", "negligible": "low", "unimportant": "low",
}
_RANK = {s: i for i, s in enumerate(models.SEVERITY_RANK)}


def enabled(db: Session) -> bool:
    return get_setting(db, "vuln_feed_enabled") == "true"


# ---------- which data a host needs ----------

def target_for(os_id: str, version_id: str):
    """
    (feed, ecosystem, compare) for an /etc/os-release ID and VERSION_ID,
    or None when there's no data for that OS.
    """
    os_id = (os_id or "").lower()
    major = (version_id or "").split(".")[0]
    if os_id == "rocky" and major:
        return "Rocky Linux", f"Rocky Linux:{major}", rpm_compare
    if os_id == "almalinux" and major:
        return "AlmaLinux", f"AlmaLinux:{major}", rpm_compare
    if os_id == "rhel" and major:
        return "Red Hat", f"Red Hat:enterprise_linux:{major}", rpm_compare
    if os_id == "debian" and major:
        return "Debian", f"Debian:{major}", dpkg_compare
    if os_id == "ubuntu" and version_id:
        yy, _, mm = version_id.partition(".")
        lts = mm == "04" and yy.isdigit() and int(yy) % 2 == 0
        return "Ubuntu", f"Ubuntu:{version_id}:LTS" if lts else f"Ubuntu:{version_id}", dpkg_compare
    return None


def host_target(db: Session, host: models.Host):
    item = os_item(db, host)
    return target_for(item.name, item.version) if item else None


def needed_feeds(db: Session) -> dict:
    """
    feed name -> the ecosystems in it the fleet's hosts run. The Go feed
    is needed when a machine has a Go tool from a vendor's repository;
    its "products:<hash>" entry makes a new PRODUCTS list read it again.
    """
    feeds = {}
    for os_item in db.query(models.HostSoftware).filter(models.HostSoftware.kind == "os").all():
        t = target_for(os_item.name, os_item.version)
        if t:
            feeds.setdefault(t[0], set()).add(t[1])
    if any(p.go for p in _fleet_products(db)):
        feeds[third_party.GO_FEED] = {third_party.GO_FEED, f"products:{third_party.products_hash()}"}
    return feeds


def _fleet_products(db: Session) -> set:
    """The PRODUCTS entries some machine has installed (by name; third-party or not)."""
    rows = db.query(models.HostSoftware.kind, models.HostSoftware.name).filter(
        models.HostSoftware.kind.in_(("rpm", "deb", "snap", "flatpak", "app"))).distinct().all()
    return {p for p in (third_party.product_for(k, n) for k, n in rows) if p}


def os_item(db: Session, host: models.Host):
    return (db.query(models.HostSoftware)
            .filter(models.HostSoftware.host_id == host.id, models.HostSoftware.kind == "os").first())


def windows_product(item):
    """The Security Update Guide's product for an "os" item, or None."""
    if not item:
        return None
    return windows_os.product_for(item.name, item.version, item.publisher, item.arch, item.source_name)


def windows_products(db: Session) -> set:
    """The Windows products the fleet's machines run."""
    items = db.query(models.HostSoftware).filter(models.HostSoftware.kind == "os").all()
    return {p for p in (windows_product(i) for i in items) if p}


def _names_for(feed: str):
    return third_party.go_modules() if feed == third_party.GO_FEED else None


# ---------- reading OSV records ----------

def _ecosystem_key(eco: str) -> str:
    # "Red Hat:enterprise_linux:9::appstream" -> "Red Hat:enterprise_linux:9"; the repo doesn't matter
    if eco.startswith("Red Hat:"):
        return ":".join(eco.split(":")[:3])
    return eco


def record_severity(rec: dict):
    """(severity, score) from what the record carries, best source first."""
    vectors = [s.get("score", "") for s in rec.get("severity") or [] if s.get("type", "").startswith("CVSS_V3")]
    scores = [x for x in (cvss3_base_score(v) for v in vectors) if x is not None]
    score = max(scores) if scores else None
    word = (rec.get("summary") or "").split(":", 1)[0].strip().lower()   # RHEL family: "Important: openssl ..."
    if word in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word], score
    for s in rec.get("severity") or []:
        if s.get("type") == "Ubuntu" and s.get("score", "").lower() in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[s["score"].lower()], score
    for a in rec.get("affected") or []:
        urgency = ((a.get("ecosystem_specific") or {}).get("urgency") or "").lower()
        if urgency in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[urgency], score
    ghsa = ((rec.get("database_specific") or {}).get("severity") or "").lower()   # GitHub: "HIGH"
    if ghsa in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[ghsa], score
    return severity_from_score(score), score


def parse_record(rec: dict, ecosystems: set, names: set = None):
    """
    (record row, package rows) for the parts of an OSV record that apply
    to `ecosystems` (and, if given, to package `names`) and name a fix,
    or None if nothing does.
    """
    if rec.get("withdrawn"):
        return None
    packages = []
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        eco = _ecosystem_key(pkg.get("ecosystem") or "")
        if eco not in ecosystems or not pkg.get("name") or (names is not None and pkg["name"] not in names):
            continue
        for r in a.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced = "0"
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif ev.get("fixed"):
                    packages.append({"ecosystem": eco, "name": pkg["name"], "introduced": introduced,
                                     "fixed": ev["fixed"]})
    if not packages:
        return None
    ids = [rec.get("id", "")] + list(rec.get("aliases") or []) + list(rec.get("upstream") or []) + \
        list(rec.get("related") or [])
    cves = sorted({i for i in ids if i.startswith("CVE-")})
    severity, score = record_severity(rec)
    summary = rec.get("summary") or (rec.get("details") or "").strip().split("\n")[0]
    refs = [r.get("url") for r in rec.get("references") or [] if r.get("url")]
    row = {"osv_id": rec["id"], "cves": " ".join(cves), "severity": severity,
           "score": "" if score is None else f"{score:.1f}", "summary": summary[:500],
           "url": (refs[0] if refs else "")[:500], "modified": rec.get("modified", "")}
    return row, packages


# ---------- storing ----------

def _delete_feed_rows(db: Session, feed: str, osv_ids=None):
    q = db.query(models.VulnRecord.id).filter(models.VulnRecord.feed == feed)
    if osv_ids is not None:
        q = q.filter(models.VulnRecord.osv_id.in_(osv_ids))
    ids = [i for (i,) in q.all()]
    for n in range(0, len(ids), 500):
        chunk = ids[n:n + 500]
        db.query(models.VulnPackage).filter(models.VulnPackage.record_id.in_(chunk)).delete(synchronize_session=False)
        db.query(models.VulnRecord).filter(models.VulnRecord.id.in_(chunk)).delete(synchronize_session=False)


def _store(db: Session, feed: str, parsed: list):
    for row, packages in parsed:
        rec = models.VulnRecord(feed=feed, **row)
        db.add(rec)
        db.flush()
        db.bulk_insert_mappings(models.VulnPackage, [dict(p, record_id=rec.id) for p in packages])


_http = requests.Session()


def _get(url: str, stream=False):
    resp = _http.get(url, timeout=TIMEOUT, stream=stream)
    if resp.status_code == 404:
        raise RuntimeError(f"no vulnerability data published at {url}")
    resp.raise_for_status()
    return resp


def _quote(name: str) -> str:
    return requests.utils.quote(name, safe=":")


def _index(feed: str) -> list:
    """(modified, id) for every record of the ecosystem, newest first."""
    text = _get(f"{BASE_URL}/{_quote(feed)}/modified_id.csv").text
    return [(r[0], r[1]) for r in csv.reader(io.StringIO(text)) if len(r) >= 2]


def full_load(db: Session, feed: str, ecosystems: set) -> int:
    """Download the feed's whole file and replace what's stored. Returns records kept."""
    cursor = (_index(feed) or [("", "")])[0][0]
    path = STATE_DIR / "osv-download.zip.part"
    try:
        with _get(f"{BASE_URL}/{_quote(feed)}/all.zip", stream=True) as resp, open(path, "wb") as f:
            size = int(resp.headers.get("Content-Length") or 0)
            free = shutil.disk_usage(STATE_DIR).free
            if size and free < size * 2 + (500 << 20):
                raise RuntimeError(f"not enough disk space next to the database for the {size >> 20} MB download "
                                   f"({free >> 20} MB free)")
            for block in resp.iter_content(1 << 20):
                f.write(block)
        loading = f"{feed}#loading"
        _delete_feed_rows(db, loading)
        kept, batch = 0, []
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.filename.endswith(".json"):
                    continue
                try:
                    parsed = parse_record(json.loads(z.read(info)), ecosystems, _names_for(feed))
                except (ValueError, KeyError):
                    continue
                if parsed:
                    batch.append(parsed)
                if len(batch) >= 1000:
                    _store(db, loading, batch)
                    db.commit()
                    kept += len(batch)
                    batch = []
        _store(db, loading, batch)
        kept += len(batch)
        # swap the new set in for the old one in one transaction
        _delete_feed_rows(db, feed)
        db.query(models.VulnRecord).filter(models.VulnRecord.feed == loading).update(
            {"feed": feed}, synchronize_session=False)
        state = _feed_state(db, feed)
        state.ecosystems = "\n".join(sorted(ecosystems))
        state.cursor = cursor
        state.loaded_at = datetime.utcnow()
        db.commit()
        return kept
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def incremental(db: Session, feed: str, ecosystems: set, state: models.VulnFeed):
    """Apply the records changed since the last refresh. Returns how many, or None if too many."""
    changed = sorted((r for r in _index(feed) if r[0] > (state.cursor or "")), reverse=True)
    if len(changed) > MAX_INCREMENTAL:
        return None
    # Download everything first, then write: the first write takes
    # SQLite's lock for the whole database, and holding it across
    # thousands of downloads stalled every agent report and console save.
    fetched = [(osv_id, _get(f"{BASE_URL}/{_quote(feed)}/{_quote(osv_id)}.json").json())
               for _modified, osv_id in changed]
    for osv_id, rec in fetched:
        _delete_feed_rows(db, feed, [osv_id])
        parsed = parse_record(rec, ecosystems, _names_for(feed))
        if parsed:
            _store(db, feed, [parsed])
    if changed:
        state.cursor = changed[0][0]
    db.commit()
    return len(changed)


def _feed_state(db: Session, feed: str) -> models.VulnFeed:
    state = db.query(models.VulnFeed).filter(models.VulnFeed.name == feed).first()
    if not state:
        state = models.VulnFeed(name=feed, ecosystems="", cursor="", records=0, error="")
        db.add(state)
        db.flush()
    return state


def refresh_feed(db: Session, feed: str, ecosystems: set, now: datetime = None):
    now = now or datetime.utcnow()
    state = _feed_state(db, feed)
    state.attempted_at = now
    db.commit()
    try:
        have = set(filter(None, (state.ecosystems or "").split("\n")))
        stale = not state.loaded_at or now - state.loaded_at > timedelta(days=FULL_RELOAD_DAYS)
        if stale or not ecosystems <= have or incremental(db, feed, have, state) is None:
            full_load(db, feed, ecosystems)
        state = _feed_state(db, feed)
        state.records = db.query(models.VulnRecord).filter(models.VulnRecord.feed == feed).count()
        state.refreshed_at = now
        state.error = ""
        db.commit()
    except Exception as e:  # noqa: BLE001 -- recorded and shown in Settings; the old data stays usable
        db.rollback()
        state = _feed_state(db, feed)
        state.error = friendly_errors.report(e, "the vulnerability source (OSV)", context=f"feed {feed}",
                                             reach_hint=friendly_errors.INTERNET, token_hint="")[:500]
        db.commit()


NVD_PREFIX = "NVD:"


def refresh_nvd_product(db: Session, cpe: str, now: datetime = None, http=None):
    """
    One product's CVEs from NVD: everything the first time (and every
    FULL_RELOAD_DAYS), after that only what changed since the last pass.
    """
    now = now or datetime.utcnow()
    feed = NVD_PREFIX + cpe
    state = _feed_state(db, feed)
    state.attempted_at = now
    db.commit()
    key = os.environ.get("KITE_NVD_API_KEY", "")
    try:
        since = datetime.fromisoformat(state.cursor) if state.cursor else None
        full = not state.loaded_at or now - state.loaded_at > timedelta(days=FULL_RELOAD_DAYS) or \
            not third_party.window_ok(since, now)
        parsed = []
        for cve in third_party.nvd_fetch(http or _http, cpe, None if full else since, now, key):
            parsed.append((cve.get("id", ""), third_party.parse_nvd(cve, cpe)))
        if full:
            _delete_feed_rows(db, feed)
            state.loaded_at = now
        else:
            _delete_feed_rows(db, feed, [i for i, _ in parsed])
        _store(db, feed, [p for _, p in parsed if p])
        state = _feed_state(db, feed)
        state.cursor = now.isoformat()
        state.records = db.query(models.VulnRecord).filter(models.VulnRecord.feed == feed).count()
        state.refreshed_at = now
        state.error = ""
        db.commit()
    except Exception as e:  # noqa: BLE001 -- recorded and shown in Settings; the old data stays usable
        db.rollback()
        state = _feed_state(db, feed)
        state.error = friendly_errors.report(e, "NVD", context=cpe, reach_hint=friendly_errors.INTERNET,
                                             token_hint="Without an API key NVD allows few requests; set KITE_NVD_API_KEY.")[:500]
        db.commit()


MSRC_PREFIX = "MSRC:"


def refresh_windows_product(db: Session, product: str, now: datetime = None, http=None):
    """
    One Windows product's CVEs from Microsoft, all of them each time: a
    few MB, and Microsoft revises old entries often enough that fetching
    only the new ones would miss changes.
    """
    now = now or datetime.utcnow()
    feed = MSRC_PREFIX + product
    state = _feed_state(db, feed)
    state.attempted_at = now
    db.commit()
    try:
        parsed = windows_os.parse(windows_os.fetch(http or _http, product), product)
        if not parsed:
            raise RuntimeError(f"Microsoft's Security Update Guide lists nothing for {product}")
        _delete_feed_rows(db, feed)
        _store(db, feed, parsed)
        state = _feed_state(db, feed)
        state.records = len(parsed)
        state.loaded_at = state.refreshed_at = now
        state.error = ""
        db.commit()
    except Exception as e:  # noqa: BLE001 -- recorded and shown in Settings; the old data stays usable
        db.rollback()
        state = _feed_state(db, feed)
        state.error = friendly_errors.report(e, "Microsoft's Security Update Guide", context=product,
                                             reach_hint=friendly_errors.INTERNET, token_hint="")[:500]
        db.commit()


def nvd_needed(db: Session) -> bool:
    return any(p.nvd for p in _fleet_products(db))


def refresh_all(db: Session):
    """Refresh every feed the fleet needs, then re-match every host."""
    if not _lock.acquire(blocking=False):
        return False
    try:
        for feed, ecosystems in sorted(needed_feeds(db).items()):
            refresh_feed(db, feed, ecosystems)
        for product in sorted(windows_products(db)):
            refresh_windows_product(db, product)
        if nvd_needed(db):
            # NVD is slow (its first load can take an hour): show what the other sources found meanwhile
            for host in db.query(models.Host).all():
                match_host(db, host)
            # every listed product, not only the fleet's: the queries say nothing about the machines
            for cpe in third_party.nvd_products():
                refresh_nvd_product(db, cpe)
        for host in db.query(models.Host).all():
            match_host(db, host)
        return True
    finally:
        _lock.release()


def refresh_in_background():
    def work():
        db = SessionLocal()
        try:
            refresh_all(db)
        except Exception:  # noqa: BLE001
            logger.exception("vulnerability refresh failed")
        finally:
            db.close()
    if _lock.locked():
        return False
    threading.Thread(target=work, daemon=True, name="vuln-refresh").start()
    return True


def refreshing() -> bool:
    return _lock.locked()


# ---------- matching ----------

_MODULE = re.compile(r"\.module[+_]")


def _modular(version: str) -> bool:
    """
    A RHEL 8+ AppStream module build ("3.12-16.module+el8.5.0+706+..."). A
    module's advisory fixes that stream's build of a package, not the
    base OS package of the same name, so the two are never compared.
    """
    return bool(_MODULE.search(version or ""))


_MODULE_CONTEXT = re.compile(r"(\.module[+_][^+]*\+\d+)\+[0-9a-f]{8}")


def _without_context(version: str) -> str:
    """
    A module build ends in its context, a hash ("...+40328+bc090241"): the
    same build made for another stream combination, not a later version.
    """
    return _MODULE_CONTEXT.sub(r"\1", version or "")


_KERNEL_ABI = re.compile(r"^linux-.*\d+\.\d+")
_DIGITS = re.compile(r"\d+(?:\.\d+)*")


def _superseded_kernels(items, compare) -> set:
    """
    Debian/Ubuntu kernels carry their version in the package name
    (linux-image-6.8.0-45-generic), so old ones linger beside the new
    under different names, and no update will ever replace them. Of each
    such family, only the newest is kept; the rest are left out of
    matching, as rpm's several kernel-core versions are.
    """
    newest = {}
    for i in items:
        if i.kind == "deb" and _KERNEL_ABI.match(i.name):
            family = _DIGITS.sub("N", i.name)
            if family not in newest or compare(i.version, newest[family].version) > 0:
                newest[family] = i
    keep = {id(i) for i in newest.values()}
    return {id(i) for i in items if i.kind == "deb" and _KERNEL_ABI.match(i.name) and id(i) not in keep}


def _installed(db: Session, host: models.Host, compare) -> dict:
    """
    name -> (installed version, package as shown). Binary and source
    names both, since advisories use either. Where several versions are
    installed (kernels), the newest counts: the old ones are on their way out.
    """
    out = {}

    def keep(name, version, shown):
        if not name or not version:
            return
        cur = out.get(name)
        if not cur or compare(version, cur[0]) > 0:
            out[name] = (version, shown)

    items = db.query(models.HostSoftware).filter(models.HostSoftware.host_id == host.id,
                                                 models.HostSoftware.kind.in_(("rpm", "deb"))).all()
    superseded = _superseded_kernels(items, compare)
    for i in items:
        if id(i) in superseded:
            continue
        keep(i.name, i.version, i.name)
        if i.source_name and i.source_name != i.name:
            # dpkg reports the source version (with epoch); rpm's source RPM name lacks the epoch, so use the binary's
            keep(i.source_name, i.source_version if i.kind == "deb" and i.source_version else i.version, i.name)
    return out


def _add(found: dict, host_id: int, cve: str, shown: str, version: str, fixed: str, rec, source: str, compare,
         nearest: bool = False):
    key = (cve, shown)
    cur = found.get(key)
    if not cur:
        found[key] = cur = {"host_id": host_id, "cve": cve, "package": shown, "installed": version,
                            "fixed": fixed, "advisories": set(), "severity": rec.severity,
                            "score": rec.score, "summary": rec.summary, "url": rec.url, "source": source}
    cur["advisories"].add(rec.osv_id)
    # a distribution's later advisory supersedes; of a vendor's release lines, the nearest fix is the one to take
    if (compare(fixed, cur["fixed"]) < 0) if nearest else (compare(fixed, cur["fixed"]) > 0):
        cur["fixed"] = fixed
    if _RANK.get(rec.severity, 99) < _RANK.get(cur["severity"], 99):
        cur["severity"] = rec.severity
    if rec.score and (not cur["score"] or float(rec.score) > float(cur["score"])):
        cur["score"] = rec.score
    if rec.osv_id.startswith(("RLSA", "ALSA", "RHSA", "USN", "DSA", "DLA", "GHSA")):
        cur["summary"], cur["url"] = rec.summary or cur["summary"], rec.url or cur["url"]


def _match_distro(db: Session, host: models.Host, target, found: dict):
    feed, ecosystem, compare = target
    installed = _installed(db, host, compare)
    names = list(installed)
    for n in range(0, len(names), 500):
        rows = (db.query(models.VulnPackage, models.VulnRecord)
                .join(models.VulnRecord, models.VulnRecord.id == models.VulnPackage.record_id)
                .filter(models.VulnRecord.feed == feed, models.VulnPackage.ecosystem == ecosystem,
                        models.VulnPackage.name.in_(names[n:n + 500])).all())
        for pkg, rec in rows:
            version, shown = installed[pkg.name]
            if _modular(version) != _modular(pkg.fixed) or \
                    compare(_without_context(version), _without_context(pkg.fixed)) >= 0:
                continue
            if pkg.introduced not in ("", "0") and compare(version, pkg.introduced) < 0:
                continue
            for cve in (rec.cves.split() if rec.cves else [rec.osv_id]):
                _add(found, host.id, cve, shown, version, pkg.fixed, rec, "distro", compare)


def _distro_names(db: Session, target, names: list) -> set:
    """Which of these names the distribution's own advisories know: then it's the distribution's package."""
    if not target or not names:
        return set()
    return {n for (n,) in db.query(models.VulnPackage.name).filter(
        models.VulnPackage.ecosystem == target[1], models.VulnPackage.name.in_(names[:900])).distinct().all()}


def _match_third_party(db: Session, host: models.Host, target, found: dict):
    items = db.query(models.HostSoftware).filter(
        models.HostSoftware.host_id == host.id,
        models.HostSoftware.kind.in_(("rpm", "deb", "snap", "flatpak", "app", "os"))).all()
    family = "windows" if any(i.kind == "os" and (i.name or "").lower().startswith("windows") for i in items) else "linux"
    mapped = [(i, third_party.product_for(i.kind, i.name)) for i in items if i.kind != "os"]
    mapped = [(i, p) for i, p in mapped if p]
    distro = _distro_names(db, target, sorted({n for i, _ in mapped for n in (i.name, i.source_name) if n}))
    for item, product in mapped:
        if not third_party.third_party(item, distro):
            continue
        version = third_party.upstream_version(item.kind, item.version)
        if not version:
            continue
        sources = [(third_party.GO_FEED, "Go", m, "go") for m in product.go
                   if third_party.go_module_applies(m, version)] + \
            [(NVD_PREFIX + c, third_party.NVD_ECOSYSTEM, c, "nvd") for c in product.nvd]
        for feed, ecosystem, name, source in sources:
            rows = (db.query(models.VulnPackage, models.VulnRecord)
                    .join(models.VulnRecord, models.VulnRecord.id == models.VulnPackage.record_id)
                    .filter(models.VulnRecord.feed == feed, models.VulnPackage.ecosystem == ecosystem,
                            models.VulnPackage.name == name).all())
            for pkg, rec in rows:
                if pkg.platforms and family not in pkg.platforms.split():
                    continue
                if not third_party.in_range(version, pkg.introduced, pkg.fixed):
                    continue
                fixed = third_party.shown_fix(pkg.fixed) if source == "nvd" else third_party.clean_version(pkg.fixed)
                for cve in (rec.cves.split() if rec.cves else [rec.osv_id]):
                    _add(found, host.id, cve, item.name, item.version, fixed, rec, source, third_party.compare,
                         nearest=True)


def _build_compare(a: str, b: str) -> int:
    x, y = windows_os.build_of(a.split()[0] if a else ""), windows_os.build_of(b.split()[0] if b else "")
    return (x > y) - (x < y) if x and y else 0


def _match_windows(db: Session, host: models.Host, found: dict):
    item = os_item(db, host)
    product = windows_product(item)
    if not product:
        return
    kbs = {(n or "").upper() for (n,) in db.query(models.HostSoftware.name).filter(
        models.HostSoftware.host_id == host.id, models.HostSoftware.kind == "kb").all()}
    fixes = {}
    rows = (db.query(models.VulnPackage, models.VulnRecord)
            .join(models.VulnRecord, models.VulnRecord.id == models.VulnPackage.record_id)
            .filter(models.VulnRecord.feed == MSRC_PREFIX + product, models.VulnPackage.ecosystem == windows_os.ECOSYSTEM,
                    models.VulnPackage.name == product).all())
    for pkg, rec in rows:
        fixes.setdefault(rec.id, (rec, []))[1].append((pkg.fixed, pkg.kb or ""))
    for rec, options in fixes.values():
        missing = windows_os.is_open(item.version, options, kbs)
        if not missing:
            continue
        fixed, kb = missing
        _add(found, host.id, rec.osv_id, item.name, item.version, f"{fixed} ({kb})" if kb else fixed, rec, "msrc",
             _build_compare)
        found[(rec.osv_id, item.name)]["advisories"] = {kb} if kb else set()


def match_host(db: Session, host: models.Host, now: datetime = None):
    """Recompute the host's HostVuln rows from its software and the stored feeds."""
    db.query(models.HostVuln).filter(models.HostVuln.host_id == host.id).delete(synchronize_session=False)
    if not enabled(db) or not host.software_reported_at:
        host.vulns_matched_at = None
        db.commit()
        return 0
    target = host_target(db, host)
    found = {}   # (cve, package) -> row
    if target:
        _match_distro(db, host, target, found)
    _match_windows(db, host, found)
    _match_third_party(db, host, target, found)
    db.bulk_insert_mappings(models.HostVuln, [
        dict(r, advisories=" ".join(sorted(r["advisories"]))) for r in found.values()])
    host.vulns_matched_at = now or datetime.utcnow()
    db.commit()
    return len(found)


def match_host_safely(db: Session, host: models.Host):
    """After a software report: a matching problem must never fail the agent's report."""
    try:
        match_host(db, host)
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("vulnerability matching failed for %s", host.hostname)


def _loaded(db: Session, feed: str):
    state = db.query(models.VulnFeed).filter(models.VulnFeed.name == feed).first()
    return state if state and state.refreshed_at else None


def third_party_loaded(db: Session):
    """When third-party data was last refreshed (the oldest source), or None if there's none yet."""
    states = [_loaded(db, third_party.GO_FEED)] + [_loaded(db, NVD_PREFIX + c) for c in third_party.nvd_products()]
    states = [x for x in states if x]
    return min(x.refreshed_at for x in states) if states else None


def coverage(db: Session, host: models.Host) -> dict:
    """Whether the host can be matched, and if not, why -- for the machine page."""
    if not enabled(db):
        return {"covered": False, "reason": "Vulnerability data is off — an admin can turn it on in Settings → Vulnerabilities."}
    if not host.software_reported_at:
        return {"covered": False, "reason": "This agent hasn't reported its software yet."}
    target = host_target(db, host)
    product = None if target else windows_product(os_item(db, host))
    vendor_at = third_party_loaded(db)
    out = {"covered": True, "third_party_refreshed_at": vendor_at, "ecosystem": None, "feed": None,
           "refreshed_at": None, "error": "", "os_note": ""}
    if target:
        state = db.query(models.VulnFeed).filter(models.VulnFeed.name == target[0]).first()
        out.update(feed=target[0], ecosystem=target[1])
        if state and state.refreshed_at:
            out.update(refreshed_at=state.refreshed_at, error=state.error or "")
        else:
            err = state.error if state and state.error else ""
            out["os_note"] = f"Data for {target[1]} hasn't been downloaded yet." + (f" Last attempt: {err}" if err else "")
    elif product:
        state = db.query(models.VulnFeed).filter(models.VulnFeed.name == MSRC_PREFIX + product).first()
        out.update(feed=MSRC_PREFIX + product, ecosystem=product)
        if state and state.refreshed_at:
            out.update(refreshed_at=state.refreshed_at, error=state.error or "")
        else:
            err = state.error if state and state.error else ""
            out["os_note"] = f"Microsoft's data for {product} hasn't been downloaded yet." + (f" Last attempt: {err}" if err else "")
        if product.startswith("Windows 10") and not re.search(r"LTS[BC]", os_item(db, host).name or ""):
            out["os_note"] = (out["os_note"] + " Windows 10 is past its end of support: Microsoft's fixes since "
                              "October 2025 install only with Extended Security Updates (ESU).").strip()
    else:
        out["os_note"] = ("The operating system itself isn't checked — RHEL, Rocky, AlmaLinux, Debian, Ubuntu and "
                          "Windows 10, 11 and Server 2012 and later are.")
    if not out["refreshed_at"] and not vendor_at:
        return {"covered": False, "reason": out["os_note"] or "No vulnerability data downloaded yet.", "feed": out["feed"]}
    return out


def _daily_pass():
    db = SessionLocal()
    try:
        if enabled(db):
            refresh_all(db)
    finally:
        db.close()


async def refresh_loop():
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            await asyncio.to_thread(_daily_pass)
        except Exception:  # noqa: BLE001 -- one bad pass must never kill the loop
            logger.exception("vulnerability refresh pass failed")
        await asyncio.sleep(PASS_SECONDS)
