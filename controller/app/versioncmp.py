"""
Comparing package versions the way the package managers do, and turning
CVSS vectors into a severity -- what vulnerability matching
(app/vulnerabilities.py) needs to decide "is this installed version
before the fix".

dpkg_compare follows Debian policy 5.6.12 (epoch, upstream, revision;
`~` sorts before everything, even the end of the string). rpm_compare
follows rpmvercmp (epoch, then version and release compared segment by
segment, numbers numerically, `~` and `^` as rpm treats them).
"""
import math
import re


def _split_evr(v: str, rpm: bool):
    v = (v or "").strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ("" if rpm else "0")
    return epoch, ver, rel


# ---------- dpkg ----------

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return -1 if diff < 0 else 1
    return 0


def dpkg_compare(a: str, b: str) -> int:
    ea, va, ra = _split_evr(a, rpm=False)
    eb, vb, rb = _split_evr(b, rpm=False)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(va, vb) or _dpkg_part(ra, rb)


# ---------- rpm ----------

_RPM_SEG = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    sa, sb = _RPM_SEG.findall(a), _RPM_SEG.findall(b)
    while sa or sb:
        if sa and sa[0] == "~" or sb and sb[0] == "~":
            if not (sa and sa[0] == "~"):
                return 1
            if not (sb and sb[0] == "~"):
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if sa and sa[0] == "^" or sb and sb[0] == "^":
            if not sa:
                return -1
            if not sb:
                return 1
            if sa[0] != "^":
                return 1
            if sb[0] != "^":
                return -1
            sa, sb = sa[1:], sb[1:]
            continue
        if not sa or not sb:
            return 1 if sa else -1
        x, y = sa[0], sb[0]
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        if x.isdigit():
            x, y = int(x), int(y)
        if x != y:
            return 1 if x > y else -1
        sa, sb = sa[1:], sb[1:]
    return 0


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _split_evr(a, rpm=True)
    eb, vb, rb = _split_evr(b, rpm=True)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _rpmvercmp(va, vb)
    if c or not (ra and rb):
        return c
    return _rpmvercmp(ra, rb)


# ---------- CVSS ----------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str):
    """Base score of a CVSS v3.x vector, or None if it can't be read."""
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min(1.08 * (impact + exploit), 10)) if changed else _roundup(min(impact + exploit, 10))
    except (KeyError, ValueError, IndexError):
        return None


def severity_from_score(score) -> str:
    """CVSS score -> kite's scale (critical / important / moderate / low)."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "important"
    if score >= 4.0:
        return "moderate"
    return "low" if score > 0 else "unknown"
