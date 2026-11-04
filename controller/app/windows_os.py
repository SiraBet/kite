"""
Vulnerabilities in Windows itself, from Microsoft's Security Update
Guide (https://msrc.microsoft.com/update-guide). Its API answers per
product -- "Windows 10 Version 22H2 for x64-based Systems", "Windows
Server 2022" -- with each CVE, the update (KB) that fixes it and the OS
build that update brings.

Windows updates are cumulative: a machine at build 10.0.19045.5000 has
every fix up to that build. So a CVE is open when the machine's build
is below the fixed build and the fixing KB isn't installed (a hotpatch
fixes without moving the build). Only the Windows products the fleet
runs are asked about: Microsoft learns those version names, nothing
about the machines.

The machine's product comes from the agent's "os" item: the build
(10.0.19045.4000), DisplayVersion ("22H2", in publisher), and the
architecture and installation type when the agent sends them (arch,
source_name); older agents send neither, which reads as x64 with a
desktop. Windows' own components only: .NET, Office and the like are
separate products in the guide and aren't matched here.
"""
import os
import re
import time

import requests

from .models import SEVERITY_RANK
from .versioncmp import severity_from_score

SUG_URL = os.environ.get("KITE_MSRC_URL",
                         "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct").rstrip("/")
GAP_SECONDS = 1.0
ECOSYSTEM = "msrc"
CVE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/"

# build -> release, for builds whose DisplayVersion is missing (before 20H2) or not yet known
WIN10 = {10240: "", 10586: "1511", 14393: "1607", 15063: "1703", 16299: "1709", 17134: "1803",
         17763: "1809", 18362: "1903", 18363: "1909", 19041: "2004", 19042: "20H2", 19043: "21H1",
         19044: "21H2", 19045: "22H2"}
WIN11 = {22000: "21H2", 22621: "22H2", 22631: "23H2", 26100: "24H2", 26200: "25H2"}
SERVER = {9200: "Windows Server 2012", 9600: "Windows Server 2012 R2", 14393: "Windows Server 2016",
          17763: "Windows Server 2019", 20348: "Windows Server 2022", 26100: "Windows Server 2025"}
_ARCH = {"x64": "x64-based Systems", "amd64": "x64-based Systems", "arm64": "ARM64-based Systems",
         "x86": "32-bit Systems"}
_RELEASE = re.compile(r"^\d\dH\d$|^\d{4}$")
_SEVERITY = {"critical": "critical", "important": "important", "moderate": "moderate", "low": "low"}


def build_of(version: str):
    """(build, revision) from "10.0.19045.4000" (or "6.3.9600.21620"), or None."""
    parts = (version or "").strip().split(".")
    if len(parts) < 4 or not parts[-1].isdigit() or not parts[-2].isdigit():
        return None
    return int(parts[-2]), int(parts[-1])


def product_for(name: str, version: str, release: str = "", arch: str = "", install_type: str = ""):
    """
    The guide's product name for a machine's "os" item, or None when it
    isn't a Windows the guide covers (or can't be told).
    """
    b = build_of(version)
    if not b or not (name or "").lower().startswith("windows"):
        return None
    build = b[0]
    if "server" in name.lower() or "server" in (install_type or "").lower():
        base = SERVER.get(build)
        if not base:
            return None
        return base + (" (Server Core installation)" if (install_type or "").lower() == "server core" else "")
    platform = _ARCH.get((arch or "x64").lower())
    if not platform:
        return None
    # Windows 11 still says "Windows 10" in ProductName; the build tells them apart
    family = "Windows 11" if build >= 22000 else "Windows 10"
    known = (WIN11 if build >= 22000 else WIN10).get(build)
    rel = release if _RELEASE.match(release or "") else known
    if rel is None:
        return None
    return f"{family} Version {rel} for {platform}" if rel else f"{family} for {platform}"


def spellings(product: str) -> list:
    """The guide isn't consistent ("Windows 11 version 26H1"), and its filter is case-sensitive."""
    out = [product]
    if " Version " in product:
        out.append(product.replace(" Version ", " version "))
    return out


def fetch(http, product: str, retries: int = 4) -> list:
    """Every entry the guide has for the product. Raises RuntimeError when it can't be read."""
    for spelling in spellings(product):
        quoted = spelling.replace("'", "''")
        url = f"{SUG_URL}?$filter=product eq '{quoted}'"
        entries = []
        while url:
            data, err = None, ""
            for attempt in range(retries):
                time.sleep(GAP_SECONDS if attempt == 0 else GAP_SECONDS * 5 * attempt)
                try:
                    resp = http.get(url, timeout=120)
                    resp.raise_for_status()
                    data = resp.json()
                    break
                except (requests.RequestException, ValueError) as e:
                    err = e
            if data is None:
                raise err
            entries.extend(data.get("value") or [])
            url = data.get("@odata.nextLink")
        if entries:
            return entries
    return []


def parse(entries: list, product: str) -> list:
    """
    (record row, package rows) per CVE, in the shape app/vulnerabilities
    stores: one package row per update that fixes it, its fixed build in
    `fixed` and the KB in `kb`. Entries naming no fixed build are left
    out: nothing to compare the machine with.
    """
    by_cve = {}
    for e in entries:
        cve = e.get("cveNumber") or ""
        if not cve:
            continue
        packages = []
        for kb in e.get("kbArticles") or []:
            fixed = (kb.get("fixedBuildNumber") or "").strip()
            if build_of(fixed):
                name = (kb.get("articleName") or "").strip()
                packages.append({"ecosystem": ECOSYSTEM, "name": product, "introduced": "0", "fixed": fixed,
                                 "kb": f"KB{name}" if name.isdigit() else name})
        if not packages:
            continue
        try:
            score = float(e.get("baseScore") or "")
        except ValueError:
            score = None
        severity = _SEVERITY.get((e.get("severity") or "").lower()) or severity_from_score(score)
        cur = by_cve.get(cve)
        if not cur:
            impact = (e.get("impact") or "").strip()
            row = {"osv_id": cve, "cves": cve, "severity": severity,
                   "score": "" if score is None else f"{score:.1f}",
                   "summary": f"Windows {impact.lower()} vulnerability" if impact else "Windows vulnerability",
                   "url": CVE_URL + cve, "modified": e.get("releaseDate") or ""}
            by_cve[cve] = cur = (row, [])
        row, pkgs = cur
        if score is not None and (not row["score"] or score > float(row["score"])):
            row["score"] = f"{score:.1f}"
        if SEVERITY_RANK.index(severity) < SEVERITY_RANK.index(row["severity"]):
            row["severity"] = severity
        seen = {(p["fixed"], p["kb"]) for p in pkgs}
        pkgs.extend(p for p in packages if (p["fixed"], p["kb"]) not in seen)
    return list(by_cve.values())


def is_open(installed_build: str, fixes: list, kbs: set):
    """
    The fix still to install, as (fixed build, KB), or None when the
    machine has one: its build is at or past a fixed build of the same
    release, or the KB is installed. Fixes for another build line are
    ignored.
    """
    have = build_of(installed_build)
    if not have:
        return None
    applicable = []
    for fixed, kb in fixes:
        want = build_of(fixed)
        if not want or want[0] != have[0]:
            continue
        if have >= want or (kb and kb.upper() in kbs):
            return None
        applicable.append((want, fixed, kb))
    if not applicable:
        return None
    _, fixed, kb = min(applicable)
    return fixed, kb
