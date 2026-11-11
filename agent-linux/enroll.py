"""
Run this once per host to enroll it: python3 enroll.py --controller ... --token ...
Writes /etc/kite/agent.conf (mode 600, root-only) with the long-lived
per-host credential. That credential is shown by the controller exactly
once, at enrollment — this script is the only place that ever sees it
in plaintext outside the DB's hash.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import ssl
import stat
import sys

import requests

CONFIG_PATH = os.environ.get("KITE_AGENT_CONFIG", "/etc/kite/agent.conf")
# The controller's root CA, which every call to the controller is checked
# against (the controller's README: "The controller's certificate authority").
CA_PATH = os.environ.get("KITE_CA_CERT_PATH", "/etc/kite/controller-ca.crt")


def ca_fingerprint(pem):
    """SHA-256 of the certificate (DER), lowercase hex: what the console and a browser show."""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def _normalise(fingerprint):
    return re.sub(r"[^0-9a-f]", "", (fingerprint or "").lower())


def fetch_controller_ca(controller, fingerprint):
    """
    Download the controller's root CA and check it against the fingerprint
    the console showed. Unverified download, verified content: nothing is
    trusted until the fingerprint matches. Returns the PEM; exits on a
    mismatch.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    resp = requests.get(f"{controller}/download/ca.crt", timeout=15, verify=False)
    if resp.status_code != 200:
        raise SystemExit(f"Couldn't download the controller's CA ({resp.status_code}): {resp.text[:200]}")
    pem = resp.text
    try:
        got = ca_fingerprint(pem)
    except ValueError:
        raise SystemExit("The controller's CA download isn't a certificate.") from None
    if got != _normalise(fingerprint):
        raise SystemExit(f"The controller's CA has fingerprint {got}, not the {_normalise(fingerprint)} "
                         "you were given. Not enrolling: something may be impersonating the controller.")
    return pem


def install_ca(pem):
    os.makedirs(os.path.dirname(CA_PATH), exist_ok=True)
    tmp = CA_PATH + ".new"
    with open(tmp, "w") as f:
        f.write(pem)
    os.chmod(tmp, 0o644)
    os.replace(tmp, CA_PATH)

# /etc/os-release ID -> normalized os_family prefix, e.g. 'rhel' + major '9'
# -> 'rhel9'. Covers the whole RHEL/dnf clone family; Windows gets its own
# detection in agent-windows/ (a separate agent entirely, not this file).
_RHEL_FAMILY_IDS = {
    "rocky": "rocky",
    "rhel": "rhel",
    "almalinux": "alma",
    "ol": "ol",          # Oracle Linux
    "centos": "centos",  # CentOS Stream 8/9 (VERSION_ID is just "8"/"9" there)
}

# Same idea for the Debian/apt family. VERSION_ID is "22.04" on Ubuntu (major
# -> "22") and a plain "12" on Debian (major -> "12") — same
# major-version-only convention as the RHEL family above, e.g. 'ubuntu22'.
_DEBIAN_FAMILY_IDS = {
    "ubuntu": "ubuntu",
    "debian": "debian",
}


def _read_os_release():
    """
    Parse /etc/os-release into a dict — the standard, vendor-maintained
    machine-readable identity file present on every RHEL-family distro
    (and virtually every modern Linux). Preferred over distro-specific
    files like /etc/rocky-release, which only exist on that one distro.
    """
    data = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k] = v.strip('"')
    except FileNotFoundError:
        pass
    return data


def detect_os_version():
    rel = _read_os_release()
    if rel.get("PRETTY_NAME"):
        return rel["PRETTY_NAME"]
    try:
        with open("/etc/rocky-release") as f:
            return f.read().strip()
    except FileNotFoundError:
        return platform.platform()


def detect_os_family():
    """
    Normalized key used to match this host against an OS-scripts folder on
    the controller, e.g. 'rocky8', 'rhel9', 'alma9', 'ol8', 'centos9',
    'ubuntu22', 'debian12'. Falls back to '' (no folder match, agent uses
    its built-in dnf/apt defaults) if this can't be determined —
    intentionally conservative rather than guessing wrong.
    """
    rel = _read_os_release()
    os_id = rel.get("ID", "")
    prefix = _RHEL_FAMILY_IDS.get(os_id) or _DEBIAN_FAMILY_IDS.get(os_id)
    if prefix:
        major = rel.get("VERSION_ID", "").split(".")[0]
        if major.isdigit():
            return f"{prefix}{major}"

    # Legacy fallback for minimal images that lack /etc/os-release entirely.
    try:
        with open("/etc/rocky-release") as f:
            text = f.read()
        # "Rocky Linux release 8.10 (Green Obsidian)" -> "rocky8"
        m = re.search(r"release (\d+)", text)
        if m:
            return f"rocky{m.group(1)}"
    except FileNotFoundError:
        pass
    return ""


def detect_smbios_uuid():
    """
    Proxmox stamps every VM with a random SMBIOS UUID (visible via
    `qm config <vmid>` on the hypervisor as the smbios1 line), and that
    same UUID shows up inside the guest here — no root needed to read it
    on most distros. The controller cross-references this against its
    Proxmox API access to figure out this host's numeric VM ID
    automatically, without anyone typing it in by hand.
    """
    try:
        with open("/sys/class/dmi/id/product_uuid") as f:
            return f.read().strip().lower()
    except (FileNotFoundError, PermissionError):
        return ""


def main():
    parser = argparse.ArgumentParser(description="Enroll this host with a kite controller")
    parser.add_argument("--controller", required=True, help="e.g. http://control-vm:8000")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="one-time enrollment token from the controller")
    group.add_argument("--secret", help="shared enrollment secret (self-enroll — see controller README)")
    parser.add_argument("--hostname", default=None,
                         help="hostname to enroll as (required with --secret; ignored with --token, "
                              "since the token is already tied to a hostname)")
    parser.add_argument("--team", default="", help="only used with --secret")
    parser.add_argument("--role", default="", help="only used with --secret")
    parser.add_argument("--os-version", default=None, help="override auto-detected OS version string")
    parser.add_argument("--os-family", default=None, help="override auto-detected OS family key, e.g. 'rocky8'")
    parser.add_argument("--vmid", type=int, default=None, help="Proxmox VM ID for this host (for the snapshot stage). Only taken with --token, and only "
                              "when the host has no VM linked yet; otherwise the controller matches the VM "
                              "by SMBIOS UUID, or an admin sets it in the console.")
    parser.add_argument("--poll-interval", type=int, default=900,
                         help="Baseline check-in interval in seconds when idle (default 900 = 15 min). "
                              "The local trigger file gives instant response for on-demand work regardless "
                              "of this setting — see the agent README.")
    parser.add_argument("--error-backoff", type=int, default=20,
                         help="Seconds to wait before retrying after a failed poll request (default 20)")
    parser.add_argument("--insecure", action="store_true",
                         help="Skip TLS certificate verification for every call to the controller, "
                              "including all future polling — needed for the self-signed cert "
                              "controller-install.sh sets up by default (see Caddyfile). Drop this "
                              "once the controller has a cert your system trusts (a real domain + "
                              "Let's Encrypt, or your own CA).")
    parser.add_argument("--ca-fingerprint", default=None,
                         help="SHA-256 fingerprint of the controller's root CA, from the console's enrol "
                              "command: the CA is downloaded, checked against it, and from then on every "
                              "call to the controller is checked against that CA.")
    parser.add_argument("--ca-cert", default=None,
                         help="the controller's root CA as a PEM file, already checked (the enrol "
                              "commands do this): same as --ca-fingerprint without the download.")
    args = parser.parse_args()

    if args.secret and not args.hostname:
        parser.error("--hostname is required when using --secret")
    controller = args.controller.rstrip("/")
    if (args.ca_fingerprint or args.ca_cert) and args.insecure:
        parser.error("--insecure turns off the certificate check that --ca-fingerprint / --ca-cert set up")
    verify = not args.insecure
    if args.ca_fingerprint or args.ca_cert:
        if args.ca_cert:
            try:
                with open(args.ca_cert) as f:
                    pem = f.read()
                ca_fingerprint(pem)
            except (OSError, ValueError) as e:
                parser.error(f"--ca-cert {args.ca_cert}: not a readable certificate ({e})")
            if args.ca_fingerprint and ca_fingerprint(pem) != _normalise(args.ca_fingerprint):
                raise SystemExit("--ca-cert doesn't match --ca-fingerprint. Not enrolling.")
        else:
            pem = fetch_controller_ca(controller, args.ca_fingerprint)
        if not (args.ca_cert and os.path.abspath(args.ca_cert) == os.path.abspath(CA_PATH)):
            install_ca(pem)
        verify = CA_PATH

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print(
            "WARNING: TLS certificate verification is DISABLED (--insecure). The "
            f"long-lived agent secret this script is about to receive from "
            f"{args.controller} -- and every command the agent later executes as "
            "root -- will cross the network with no protection against "
            "interception or tampering. Use this only if you accept that risk "
            "(e.g. a trusted private network) and drop --insecure as soon as the "
            "controller has a certificate this host trusts.",
            file=sys.stderr,
        )

    os_version = args.os_version or detect_os_version()
    os_family = args.os_family if args.os_family is not None else detect_os_family()
    smbios_uuid = detect_smbios_uuid()

    if args.token:
        resp = requests.post(
            f"{controller}/agent/enroll",
            json={"token": args.token, "os_version": os_version, "os_family": os_family,
                  "smbios_uuid": smbios_uuid, "poll_interval_seconds": args.poll_interval,
                  "proxmox_vmid": args.vmid},
            timeout=15, verify=verify,
        )
    else:
        resp = requests.post(
            f"{controller}/agent/self-enroll",
            json={
                "secret": args.secret, "hostname": args.hostname, "team": args.team, "role": args.role,
                "os_version": os_version, "os_family": os_family,
                "smbios_uuid": smbios_uuid, "poll_interval_seconds": args.poll_interval,
                "proxmox_vmid": args.vmid,
            },
            timeout=15, verify=verify,
        )

    if resp.status_code >= 300:
        print(f"Enrollment failed ({resp.status_code}): {resp.text}")
        raise SystemExit(1)
    data = resp.json()

    config = {
        "controller_url": args.controller.rstrip("/"),
        "host_id": data["host_id"],
        "agent_secret": data["agent_secret"],
        "poll_interval": args.poll_interval,
        "error_backoff": args.error_backoff,
        "verify_tls": not args.insecure,
    }
    if verify == CA_PATH:
        config["ca_cert"] = CA_PATH

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 600, root-only

    print(f"Enrolled as host_id={data['host_id']} (os_family='{os_family}'). Config written to {CONFIG_PATH} (mode 600).")
    print("Next: systemctl daemon-reload && systemctl enable --now kite-agent")


if __name__ == "__main__":
    main()
