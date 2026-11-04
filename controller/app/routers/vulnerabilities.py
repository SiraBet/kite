"""
CVEs the fleet is exposed to (app/vulnerabilities.py): per machine, across
the fleet, and the state of the downloaded data. Anyone signed in can
read; refreshing the data is an admin's, as is turning it on (the
vuln_feed_enabled setting, PUT /settings/vuln_feed_enabled).
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

from .. import audit, models, third_party, vulnerabilities, windows_os
from ..auth import get_current_user, require_role
from ..db import get_db

router = APIRouter(tags=["vulnerabilities"])
_RANK = {s: i for i, s in enumerate(models.SEVERITY_RANK)}


def _counts(rows) -> dict:
    out = {s: 0 for s in models.SEVERITY_RANK}
    seen = set()
    for r in rows:
        if r.cve not in seen:
            seen.add(r.cve)
            out[r.severity if r.severity in out else "unknown"] += 1
    out["total"] = len(seen)
    return out


def _group(rows) -> list:
    """One entry per CVE, its affected packages listed under it, most severe first."""
    by_cve = {}
    for r in rows:
        v = by_cve.setdefault(r.cve, {"cve": r.cve, "severity": r.severity, "score": r.score, "summary": r.summary,
                                      "url": r.url, "advisories": set(), "packages": [], "source": r.source or "distro"})
        v["advisories"].update((r.advisories or "").split())
        v["packages"].append({"name": r.package, "installed": r.installed, "fixed": r.fixed})
        if _RANK.get(r.severity, 99) < _RANK.get(v["severity"], 99):
            v["severity"] = r.severity
        if r.score and (not v["score"] or float(r.score) > float(v["score"])):
            v["score"] = r.score
    out = []
    for v in by_cve.values():
        v["advisories"] = sorted(v["advisories"])
        v["packages"].sort(key=lambda p: p["name"])
        out.append(v)
    out.sort(key=lambda v: (_RANK.get(v["severity"], 99), -float(v["score"] or 0), v["cve"]))
    return out


def _windows_fix(rows):
    """
    Windows updates are cumulative: the newest one named fixes every
    Windows CVE the machine has open. {"fix": "10.0.x.y (KBn)", "count": n} or None.
    """
    rows = [r for r in rows if r.source == "msrc"]
    if not rows:
        return None
    newest = max(rows, key=lambda r: windows_os.build_of(r.fixed.split()[0]) or (0, 0))
    return {"fix": newest.fixed, "count": len({r.cve for r in rows})}


@router.get("/hosts/{host_id}/vulnerabilities")
def host_vulnerabilities(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    rows = db.query(models.HostVuln).filter(models.HostVuln.host_id == host.id).all()
    return {**vulnerabilities.coverage(db, host), "matched_at": host.vulns_matched_at,
            "counts": _counts(rows), "items": _group(rows), "windows_fix": _windows_fix(rows)}


@router.get("/vulnerabilities")
def fleet_vulnerabilities(cve: Optional[str] = None, severity: Optional[str] = None, limit: int = 500,
                          db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """
    Every CVE some host is exposed to, with the hosts. `cve` matches part of
    an id ("2024-6387" finds CVE-2024-6387) or a package name; `severity`
    keeps one level.
    """
    HV = models.HostVuln
    conds = []
    if cve:
        term = f"%{cve.strip()}%"
        conds.append(HV.cve.ilike(term) | HV.package.ilike(term) | HV.advisories.ilike(term))
    if severity:
        conds.append(HV.severity == severity)
    # One row per CVE from the database (worst severity, host count), not
    # one per host x package x CVE: a fleet's worth of those is far more
    # than any page shows. Per-host detail is read for the shown page only.
    rank = case(*[(HV.severity == s, i) for s, i in _RANK.items()], else_=99)
    summary = (db.query(HV.cve, func.min(rank), func.count(distinct(HV.host_id)),
                        func.max(HV.score), func.max(HV.summary), func.max(HV.url), func.max(HV.source))
               .join(models.Host, models.Host.id == HV.host_id).filter(*conds).group_by(HV.cve).all())
    by_rank = {i: s for s, i in _RANK.items()}

    def score(v):
        try:
            return float(v or 0)
        except ValueError:
            return 0.0
    summary.sort(key=lambda r: (r[1], -r[2], -score(r[3]), r[0]))
    page = summary[:max(1, min(limit, 5000))]
    items = {r[0]: {"cve": r[0], "severity": by_rank.get(r[1], "unknown"), "score": r[3], "summary": r[4],
                    "url": r[5], "source": r[6] or "distro", "host_count": r[2], "hosts": {}}
             for r in page}
    if items:
        rows = (db.query(HV.cve, HV.host_id, models.Host.hostname, HV.package, HV.installed, HV.fixed)
                .join(models.Host, models.Host.id == HV.host_id)
                .filter(HV.cve.in_(list(items)), *conds).all())
        for cve_id, host_id, hostname, package, installed, fixed in rows:
            h = items[cve_id]["hosts"].setdefault(host_id, {"host_id": host_id, "hostname": hostname, "packages": []})
            h["packages"].append({"name": package, "installed": installed, "fixed": fixed})
    out = []
    for r in page:
        v = items[r[0]]
        v["hosts"] = sorted(v["hosts"].values(), key=lambda h: h["hostname"].lower())
        out.append(v)
    return {"total": len(summary), "items": out, "enabled": vulnerabilities.enabled(db)}


FEED_LABELS = {third_party.GO_FEED: "Go tools — GitHub advisories via OSV", "NVD": "Other vendors' software — NVD",
               "Windows": "Windows — Microsoft Security Update Guide"}


@router.get("/vulnerabilities/status")
def vulnerability_status(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    needed = vulnerabilities.needed_feeds(db)
    feeds = {f.name: f for f in db.query(models.VulnFeed).all() if "#" not in f.name}
    out = []
    for name in sorted(n for n in set(needed) | set(feeds)
                       if not n.startswith((vulnerabilities.NVD_PREFIX, vulnerabilities.MSRC_PREFIX))):
        f = feeds.get(name)
        out.append({"name": name, "label": FEED_LABELS.get(name, f"{name} security advisories"),
                    "needed": name in needed,
                    "ecosystems": sorted(e for e in needed.get(name, []) if not e.startswith("products:"))
                    if name != third_party.GO_FEED else [],
                    "records": f.records if f else 0, "refreshed_at": f.refreshed_at if f else None,
                    "loaded_at": f.loaded_at if f else None, "attempted_at": f.attempted_at if f else None,
                    "error": f.error if f else ""})
    # Windows: one feed per Windows product the fleet runs, shown as one source
    windows = sorted(vulnerabilities.windows_products(db))
    if windows or any(n.startswith(vulnerabilities.MSRC_PREFIX) for n in feeds):
        wanted = [feeds.get(vulnerabilities.MSRC_PREFIX + p) for p in windows]
        done = [f for f in wanted if f and f.refreshed_at]
        errors = [f"{f.name[len(vulnerabilities.MSRC_PREFIX):]}: {f.error}" for f in wanted if f and f.error]
        out.append({"name": "Windows", "label": FEED_LABELS["Windows"], "needed": bool(windows),
                    "ecosystems": windows,
                    "records": sum(f.records or 0 for f in wanted if f),
                    "refreshed_at": min(f.refreshed_at for f in done) if done and len(done) == len(wanted) else None,
                    "loaded_at": None,
                    "attempted_at": max((f.attempted_at for f in wanted if f and f.attempted_at), default=None),
                    "error": "; ".join(errors)})
    # NVD is fetched product by product; shown as one source
    products = third_party.nvd_products()
    nvd = [feeds.get(vulnerabilities.NVD_PREFIX + c) for c in products]
    nvd_needed = vulnerabilities.nvd_needed(db)
    if nvd_needed or any(nvd):
        done = [f for f in nvd if f and f.refreshed_at]
        errors = [f"{f.name[len(vulnerabilities.NVD_PREFIX):]}: {f.error}" for f in nvd if f and f.error]
        out.append({"name": "NVD", "label": FEED_LABELS["NVD"], "needed": nvd_needed,
                    "ecosystems": [f"{len(done)} of {len(products)} products"],
                    "records": sum(f.records or 0 for f in nvd if f),
                    "refreshed_at": min(f.refreshed_at for f in done) if len(done) == len(products) else None,
                    "loaded_at": None, "attempted_at": max((f.attempted_at for f in nvd if f and f.attempted_at), default=None),
                    "error": "; ".join(errors[:3]) + (f" (+{len(errors) - 3} more)" if len(errors) > 3 else "")})
    return {"enabled": vulnerabilities.enabled(db), "refreshing": vulnerabilities.refreshing(),
            "source": vulnerabilities.BASE_URL, "nvd": third_party.NVD_URL, "msrc": windows_os.SUG_URL, "feeds": out}


@router.post("/vulnerabilities/refresh")
def refresh_now(db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    if not vulnerabilities.enabled(db):
        raise HTTPException(400, "Vulnerability data is off — turn it on first.")
    if not vulnerabilities.refresh_in_background():
        return {"ok": True, "note": "a refresh is already running"}
    audit.log(db, actor=user.username, role=user.role, action="vuln_refresh", detail="vulnerability data refresh started")
    return {"ok": True}
