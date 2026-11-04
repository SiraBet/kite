"""
Vulnerabilities in software that doesn't come from the distribution --
vendor repositories (Docker, NodeSource, PGDG, HashiCorp, Elastic...),
snaps, flatpaks and Windows programs. The distributions' advisories
(app/vulnerabilities.py) don't cover these, so they're matched against:

  OSV "Go"  GitHub/Go advisories, for tools written in Go (Docker,
            containerd, Vault, ...): exact fixed versions, one ~13 MB file
            from the same bucket as the distribution data.
  NVD       the US National Vulnerability Database's API, per product,
            for everything else. NVD's version data is less precise than
            a distribution's, and NVD hasn't analysed every recent CVE
            ("Deferred"), so what it misses can't show here.

Which installed package is which product is a fixed list (PRODUCTS),
matched by name, and only for packages that didn't come from the
distribution: a distribution's own nginx or postgresql has backported
fixes that upstream version numbers can't show. Every listed product is
queried, whether or not a machine has it, so the queries say nothing
about the fleet.
"""
import hashlib
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

import requests

from .versioncmp import cvss3_base_score, severity_from_score, _rpmvercmp

NVD_URL = os.environ.get("KITE_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_PAGE = 200                 # NVD drops big responses part-way; small pages and retries get through
NVD_GAP_SECONDS = 6.5          # the public limit is 5 requests in 30 s; with an API key, 50
NVD_GAP_WITH_KEY = 0.7
NVD_MAX_WINDOW_DAYS = 119      # lastModStartDate..lastModEndDate may span at most 120 days
GO_FEED = "Go"
NVD_ECOSYSTEM = "nvd"


@dataclass(frozen=True)
class Product:
    label: str
    kinds: tuple          # which software kinds: rpm deb snap flatpak app
    names: str            # regex, whole name, case-insensitive
    go: tuple = ()        # OSV Go module paths
    nvd: tuple = ()       # NVD CPE "vendor:product"


_PKG = ("rpm", "deb")
PRODUCTS = (
    # --- Go: OSV ---
    Product("Docker Engine", _PKG, r"docker-ce|docker-engine|moby-engine", go=("github.com/docker/docker", "github.com/moby/moby")),
    Product("Docker CLI", _PKG, r"docker-ce-cli|moby-cli", go=("github.com/docker/cli",)),
    Product("Docker Buildx", _PKG, r"docker-buildx-plugin|moby-buildx", go=("github.com/docker/buildx",)),
    Product("Docker Compose", _PKG, r"docker-compose-plugin|moby-compose", go=("github.com/docker/compose/v2",)),
    Product("containerd", _PKG, r"containerd\.io|containerd", go=("github.com/containerd/containerd", "github.com/containerd/containerd/v2")),
    Product("Vault", _PKG, r"vault|vault-enterprise", go=("github.com/hashicorp/vault",)),
    Product("Consul", _PKG, r"consul|consul-enterprise", go=("github.com/hashicorp/consul",)),
    Product("Nomad", _PKG, r"nomad|nomad-enterprise", go=("github.com/hashicorp/nomad",)),
    Product("Terraform", _PKG, r"terraform", go=("github.com/hashicorp/terraform",)),
    Product("NVIDIA Container Toolkit", _PKG, r"nvidia-container-toolkit",
            go=("github.com/NVIDIA/nvidia-container-toolkit",), nvd=("nvidia:nvidia_container_toolkit",)),
    Product("Tailscale", _PKG + ("app",), r"tailscale", go=("tailscale.com",)),
    Product("Caddy", _PKG, r"caddy", go=("github.com/caddyserver/caddy/v2",)),
    Product("Teleport", _PKG, r"teleport|teleport-ent", go=("github.com/gravitational/teleport",)),
    Product("Elastic Beats", _PKG, r"filebeat|metricbeat|auditbeat|packetbeat|heartbeat-elastic",
            go=("github.com/elastic/beats/v7",)),
    Product("Helm", _PKG, r"helm", go=("helm.sh/helm/v3",)),
    Product("Kubernetes", _PKG, r"kubelet|kubeadm|kubectl", go=("k8s.io/kubernetes",)),
    # --- NVD ---
    Product("Node.js", _PKG + ("app",), r"nodejs|node\.js", nvd=("nodejs:node.js",)),
    Product("PostgreSQL", _PKG + ("app",), r"postgresql\d+-server|postgresql-\d+|postgresql \d+.*", nvd=("postgresql:postgresql",)),
    Product("Zabbix", _PKG + ("app",), r"zabbix-agent2?|zabbix-(server|proxy)-\w+|zabbix agent.*", nvd=("zabbix:zabbix",)),
    # NVD has one "wazuh" for all of it and most of its CVEs are the manager's; an agent would drown in them
    Product("Wazuh", _PKG, r"wazuh-(manager|indexer)", nvd=("wazuh:wazuh",)),
    Product("Fluent Bit", _PKG, r"fluent-bit|td-agent-bit", nvd=("treasuredata:fluent_bit",)),
    Product("Elasticsearch", _PKG, r"elasticsearch", nvd=("elastic:elasticsearch",)),
    Product("Kibana", _PKG, r"kibana", nvd=("elastic:kibana",)),
    Product("Logstash", _PKG, r"logstash", nvd=("elastic:logstash",)),
    Product("Grafana", _PKG, r"grafana|grafana-enterprise", nvd=("grafana:grafana",)),
    Product("nginx", _PKG, r"nginx", nvd=("f5:nginx", "nginx:nginx")),
    Product("MongoDB", _PKG, r"mongodb-org-server", nvd=("mongodb:mongodb",)),
    Product("MySQL", _PKG, r"mysql-community-server", nvd=("oracle:mysql",)),
    Product("MariaDB", _PKG, r"mariadb-server", nvd=("mariadb:mariadb",)),
    Product("Redis", _PKG, r"redis|redis-server", nvd=("redis:redis",)),
    Product("HAProxy", _PKG, r"haproxy", nvd=("haproxy:haproxy",)),
    Product("GitLab", _PKG, r"gitlab-ce|gitlab-ee", nvd=("gitlab:gitlab",)),
    Product("Google Chrome", _PKG + ("app", "flatpak"), r"google-chrome-stable|google chrome|com\.google\.chrome",
            nvd=("google:chrome",)),
    Product("Microsoft Edge", _PKG + ("app",), r"microsoft-edge-stable|microsoft edge", nvd=("microsoft:edge", "microsoft:edge_chromium")),
    Product("Firefox ESR", _PKG + ("app",), r"firefox-esr|mozilla firefox esr.*", nvd=("mozilla:firefox_esr",)),
    Product("Firefox", _PKG + ("app", "snap", "flatpak"), r"firefox|mozilla firefox(?! esr).*|org\.mozilla\.firefox",
            nvd=("mozilla:firefox",)),
    Product("Thunderbird", _PKG + ("app", "snap", "flatpak"), r"thunderbird|mozilla thunderbird.*|org\.mozilla\.thunderbird",
            nvd=("mozilla:thunderbird",)),
    Product("Visual Studio Code", _PKG + ("app", "snap", "flatpak"), r"code|microsoft visual studio code.*|com\.visualstudio\.code",
            nvd=("microsoft:visual_studio_code",)),
    Product("7-Zip", ("app",), r"7-zip.*", nvd=("7-zip:7-zip",)),
    Product("Notepad++", ("app",), r"notepad\+\+.*", nvd=("notepad-plus-plus:notepad\\+\\+",)),
    Product("VLC", ("app", "flatpak"), r"vlc media player|org\.videolan\.vlc", nvd=("videolan:vlc_media_player",)),
    Product("PuTTY", ("app",), r"putty.*", nvd=("putty:putty",)),
    Product("WinSCP", ("app",), r"winscp.*", nvd=("winscp:winscp",)),
    Product("Git for Windows", ("app",), r"git", nvd=("git-scm:git",)),
    Product("Wireshark", ("app",), r"wireshark.*", nvd=("wireshark:wireshark",)),
    Product("FileZilla", ("app",), r"filezilla.*", nvd=("filezilla-project:filezilla_client",)),
    Product("KeePass", ("app",), r"keepass password safe.*", nvd=("keepass:keepass",)),
    Product("Docker Desktop", ("app",), r"docker desktop", nvd=("docker:desktop",)),
    Product("TeamViewer", ("app",), r"teamviewer.*", nvd=("teamviewer:teamviewer",)),
)
_COMPILED = [(p, re.compile(p.names, re.I)) for p in PRODUCTS]


def products_hash() -> str:
    """Changes when the list does, so the Go file is read again for new modules."""
    return hashlib.sha256(repr(PRODUCTS).encode()).hexdigest()[:12]


def go_modules() -> set:
    return {m for p in PRODUCTS for m in p.go}


def nvd_products() -> list:
    return sorted({c for p in PRODUCTS for c in p.nvd})


def product_for(kind: str, name: str):
    for p, rx in _COMPILED:
        if kind in p.kinds and rx.fullmatch(name or ""):
            return p
    return None


# ---------- which packages are third-party ----------

_DISTRO_VENDOR = re.compile(r"^(rocky|red hat|almalinux|centos|oracle america|amazon|cloudlinux|scientific linux)", re.I)
# Ubuntu's "0ubuntu3.4", "ubuntu0.24.04.1", "build1"; Debian's "+deb12u1". Not
# Docker's "~ubuntu.24.04~noble" or "~debian.12~bookworm": those are vendor builds.
_DISTRO_DEB_VERSION = re.compile(r"ubuntu\d|[+~]deb\d+u\d|build\d")
_PLAIN_DEB_VERSION = re.compile(r"(\d+:)?[\w.+]+-[\d.]+")


def third_party(item, distro_names: set) -> bool:
    """
    Didn't come from the distribution. rpm packages say who built them
    (and the distribution always says). A deb doesn't, so its version has
    to tell: an Ubuntu/Debian build marker means the distribution's, and
    a plain "1.22.1-9" of a package the distribution ships is its too;
    "18.20.4-1nodesource1" or "16.4-1.pgdg120+1" is a vendor's.
    """
    if item.kind == "rpm":
        return not _DISTRO_VENDOR.match(item.publisher or "")
    if item.kind == "deb":
        v = item.version or ""
        if _DISTRO_DEB_VERSION.search(v):
            return False
        known = (item.source_name or item.name) in distro_names or item.name in distro_names
        return not (known and _PLAIN_DEB_VERSION.fullmatch(v))
    return item.kind in ("snap", "flatpak", "app")


# ---------- versions ----------

def upstream_version(kind: str, version: str) -> str:
    """The vendor's own version: no epoch, no packaging release ("2:20.11.1-1nodesource" -> "20.11.1")."""
    v = (version or "").strip()
    if re.match(r"^\d+:", v):
        v = v.split(":", 1)[1]
    if kind in ("rpm", "deb", "snap") and "-" in v:
        v = v.rsplit("-", 1)[0]
    return clean_version(v)


def clean_version(v: str) -> str:
    v = (v or "").strip().lstrip("vV")
    v = v.split("+incompatible")[0]
    return re.sub(r"(\.0)+$", "", v) if re.fullmatch(r"[\d.]+", v) else v


def go_module_applies(module: str, version: str) -> bool:
    """
    A Go module path ending in /vN holds major version N only
    (github.com/containerd/containerd/v2 is containerd 2.x); a path
    without one, majors 0 and 1 -- or any, for "+incompatible" modules
    like github.com/docker/docker, which can't be told apart.
    """
    m = re.search(r"/v(\d+)$", module)
    major = (clean_version(version).split(".") or ["0"])[0]
    if m:
        return major == m.group(1)
    return True


def compare(a: str, b: str) -> int:
    """Upstream versions, numerically by segment ("1.10" > "1.9", "0.81.0.0" == "0.81")."""
    return _rpmvercmp(clean_version(a), clean_version(b))


def in_range(version: str, introduced: str, fixed: str) -> bool:
    """
    For NVD rows: introduced is "", "[x" (from x) or "(x" (after x);
    fixed is "<x", "<=x" or "=x". For Go rows: plain versions, as OSV.
    """
    if introduced:
        op, v = (introduced[0], introduced[1:]) if introduced[0] in "[(" else ("[", introduced)
        if v not in ("", "0"):
            c = compare(version, v)
            if c < 0 or (op == "(" and c == 0):
                return False
    if fixed.startswith("<="):
        return compare(version, fixed[2:]) <= 0
    if fixed.startswith("<"):
        return compare(version, fixed[1:]) < 0
    if fixed.startswith("="):
        return compare(version, fixed[1:]) == 0
    return compare(version, fixed) < 0


def shown_fix(fixed: str) -> str:
    if fixed.startswith("<="):
        return f"a version after {fixed[2:]}"
    if fixed.startswith("<"):
        return fixed[1:]
    if fixed.startswith("="):
        return "a later version"
    return fixed


# ---------- NVD records ----------

def _platform(cpe: str):
    p = cpe.split(":")
    if len(p) < 5 or p[2] not in ("o", "h"):
        return None
    vp = f"{p[3]}:{p[4]}"
    if p[3] == "microsoft" and p[4].startswith("windows"):
        return "windows"
    if p[3] == "apple" and p[4] in ("macos", "mac_os_x", "mac_os"):
        return "macos"
    if p[3] == "apple" and p[4] in ("iphone_os", "ipados", "ios"):
        return "ios"
    if vp == "google:android":
        return "android"
    if "linux" in p[4]:
        return "linux"
    return None


def nvd_score(cve: dict):
    best = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            d = m.get("cvssData") or {}
            s = d.get("baseScore")
            if s is None and d.get("vectorString", "").startswith("CVSS:3"):
                s = cvss3_base_score(d["vectorString"])
            if s is not None and (m.get("type") == "Primary" or best is None):
                best = float(s)
        if best is not None:
            return best
    return None


def parse_nvd(cve: dict, cpe: str):
    """(record row, package rows) for one product of an NVD CVE, or None."""
    if cve.get("vulnStatus") == "Rejected":
        return None
    vendor, product = cpe.split(":", 1)
    packages = []
    for conf in cve.get("configurations") or []:
        matches = [m for node in conf.get("nodes") or [] for m in node.get("cpeMatch") or []]
        platforms = {_platform(m["criteria"]) for m in matches if not m.get("vulnerable")} - {None}
        for m in matches:
            p = (m.get("criteria") or "").split(":")
            if not m.get("vulnerable") or len(p) < 6 or p[3].replace("\\", "") != vendor.replace("\\", "") \
                    or p[4].replace("\\", "") != product.replace("\\", ""):
                continue
            if m.get("versionEndExcluding"):
                fixed = "<" + m["versionEndExcluding"]
            elif m.get("versionEndIncluding"):
                fixed = "<=" + m["versionEndIncluding"]
            elif p[5] not in ("*", "-", ""):
                fixed = "=" + p[5].replace("\\", "")
            else:
                continue   # "every version": no bound to compare against
            introduced = "[" + m["versionStartIncluding"] if m.get("versionStartIncluding") else \
                "(" + m["versionStartExcluding"] if m.get("versionStartExcluding") else ""
            row = {"ecosystem": NVD_ECOSYSTEM, "name": cpe, "introduced": introduced, "fixed": fixed,
                   "platforms": " ".join(sorted(platforms))}
            if row not in packages:
                packages.append(row)
    if not packages:
        return None
    score = nvd_score(cve)
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    return ({"osv_id": cve["id"], "cves": cve["id"], "severity": severity_from_score(score),
             "score": "" if score is None else f"{score:.1f}", "summary": desc.strip()[:300],
             "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}", "modified": cve.get("lastModified", "")},
            packages)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def nvd_fetch(http, cpe: str, since: datetime = None, until: datetime = None, api_key: str = "",
              retries: int = 4):
    """
    Every CVE NVD lists for the product (changed since `since`, if given),
    page by page. Raises RuntimeError when NVD can't be read.
    """
    params = {"virtualMatchString": f"cpe:2.3:a:{cpe}", "resultsPerPage": NVD_PAGE, "startIndex": 0}
    if since:
        params.update(lastModStartDate=_iso(since), lastModEndDate=_iso(until or datetime.utcnow()))
    headers = {"apiKey": api_key} if api_key else {}
    gap = NVD_GAP_WITH_KEY if api_key else NVD_GAP_SECONDS
    total = None
    while total is None or params["startIndex"] < total:
        data, err = None, ""
        for attempt in range(retries):
            time.sleep(gap if attempt == 0 else gap * 3 * attempt)
            try:
                resp = http.get(NVD_URL, params=params, headers=headers, timeout=120)
                if resp.status_code == 404:
                    raise RuntimeError(f"NVD has no product {cpe}")
                resp.raise_for_status()
                data = resp.json()
                break
            except (requests.RequestException, ValueError) as e:
                err = e
        if data is None:
            raise err
        total = int(data.get("totalResults") or 0)
        for v in data.get("vulnerabilities") or []:
            yield v.get("cve") or {}
        params["startIndex"] += NVD_PAGE


def window_ok(since: datetime, now: datetime) -> bool:
    return since is not None and now - since < timedelta(days=NVD_MAX_WINDOW_DAYS)
