Name:           kite-agent
Version:        1.0.0
Release:        1%{?dist}
Summary:        kite fleet patch-management agent
License:        Proprietary
BuildArch:      noarch
URL:            https://internal.example/kite

Requires:       python3
Requires:       python3-pip
Requires:       python3-requests
Requires:       dnf-utils

%description
Agent for the kite fleet patch-management console. Polls a controller
for patch jobs (preflight checks, exclude/pin application, dnf update,
reboot handling, health check) and executes them locally as root.
Enrollment (pairing with a controller) happens after install — see
"Next steps" printed at the end of installation, or the project README.

%prep
# no source archive to unpack — files are staged directly into SOURCES by build.sh

%build
# pure Python, nothing to compile

%install
mkdir -p %{buildroot}/opt/kite-agent
mkdir -p %{buildroot}/etc/kite
mkdir -p %{buildroot}/var/lib/kite
mkdir -p %{buildroot}/usr/lib/systemd/system

install -m 755 %{_sourcedir}/agent.py %{buildroot}/opt/kite-agent/agent.py
install -m 755 %{_sourcedir}/enroll.py %{buildroot}/opt/kite-agent/enroll.py
install -m 644 %{_sourcedir}/kite-agent.service %{buildroot}/usr/lib/systemd/system/kite-agent.service

%files
%attr(0755,root,root) /opt/kite-agent/agent.py
%attr(0755,root,root) /opt/kite-agent/enroll.py
%dir %attr(0700,root,root) /etc/kite
%dir %attr(0700,root,root) /var/lib/kite
/usr/lib/systemd/system/kite-agent.service

%post
# The versionlock plugin package name differs between Rocky 8 and 9's repos
# (confirmed during this project's own Rocky 8.10 testing) — try both rather
# than hard-Requiring one, which would make this package fail to install on
# whichever major version doesn't use that name.
dnf install -y python3-dnf-plugin-versionlock >/dev/null 2>&1 || \
  dnf install -y python3-dnf-plugins-extras-versionlock >/dev/null 2>&1 || \
  echo "kite-agent: WARNING - could not install a versionlock plugin package under either known name. Pin-mode patch definitions will fail at the 'excludes' stage until this is resolved by hand."

systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$1" -eq 1 ] ; then
  # Fresh install. Two ways to auto-enroll right here, both via env vars
  # (rpm/dnf scriptlets inherit the invoking shell's exported vars):
  #   - KITE_CONTROLLER + KITE_TOKEN     (one-time token, tightest scope)
  #   - KITE_CONTROLLER + KITE_SECRET     (shared secret, reusable across
  #     the whole fleet's install commands — same pattern as Wazuh's authd
  #     password or Qualys's Activation ID; needs KITE_HOSTNAME too, or
  #     falls back to this host's actual hostname)
  # Either path replaces itself with a unique per-host credential on success,
  # so the token/secret is never touched again after this install.
  #
  # A failure here must NOT fail the package install itself (rpm treats a
  # non-zero %post exit as a failed transaction even though the files are
  # already in place) — so every step below is guarded to fall through to
  # the manual instructions instead of aborting.
  if [ -n "${KITE_CONTROLLER:-}" ] && [ -n "${KITE_TOKEN:-}" ]; then
    echo "kite-agent: KITE_TOKEN set — enrolling automatically..."
    ENROLL_ARGS="--controller $KITE_CONTROLLER --token $KITE_TOKEN"
    [ -n "${KITE_OS_FAMILY:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --os-family $KITE_OS_FAMILY"
    [ -n "${KITE_VMID:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --vmid $KITE_VMID"
    [ -n "${KITE_INSECURE:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --insecure"
    [ -n "${KITE_CA_CERT:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --ca-cert $KITE_CA_CERT"
    [ -n "${KITE_CA_FINGERPRINT:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --ca-fingerprint $KITE_CA_FINGERPRINT"
    AUTO_ENROLL=1
  elif [ -n "${KITE_CONTROLLER:-}" ] && [ -n "${KITE_SECRET:-}" ]; then
    HOSTNAME_TO_USE="${KITE_HOSTNAME:-$(hostname)}"
    echo "kite-agent: KITE_SECRET set — self-enrolling as '$HOSTNAME_TO_USE'..."
    ENROLL_ARGS="--controller $KITE_CONTROLLER --secret $KITE_SECRET --hostname $HOSTNAME_TO_USE"
    [ -n "${KITE_TEAM:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --team $KITE_TEAM"
    [ -n "${KITE_ROLE:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --role $KITE_ROLE"
    [ -n "${KITE_OS_FAMILY:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --os-family $KITE_OS_FAMILY"
    [ -n "${KITE_VMID:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --vmid $KITE_VMID"
    [ -n "${KITE_INSECURE:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --insecure"
    [ -n "${KITE_CA_CERT:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --ca-cert $KITE_CA_CERT"
    [ -n "${KITE_CA_FINGERPRINT:-}" ] && ENROLL_ARGS="$ENROLL_ARGS --ca-fingerprint $KITE_CA_FINGERPRINT"
    AUTO_ENROLL=1
  else
    AUTO_ENROLL=0
  fi

  if [ "$AUTO_ENROLL" -eq 1 ]; then
    if python3 /opt/kite-agent/enroll.py $ENROLL_ARGS; then
      systemctl enable --now kite-agent >/dev/null 2>&1
      echo "kite-agent: enrolled and started."
    else
      echo ""
      echo "kite-agent: auto-enroll FAILED (bad/expired credential, or controller unreachable)."
      echo "Enroll manually once you have a working credential:"
      echo "  python3 /opt/kite-agent/enroll.py --controller <controller-url> --token <token>"
      echo "  systemctl enable --now kite-agent"
    fi
  else
    echo ""
    echo "=== kite-agent installed ==="
    echo "With the controller's default self-signed certificate, add the console's"
    echo "--ca-fingerprint <sha256> (enroll.py) / KITE_CA_FINGERPRINT=<sha256>"
    echo "(dnf install) below: the controller's CA is checked, then pinned."
    echo "Next steps:"
    echo "  1. Get a one-time enrollment token: the controller's console, Fleet -> Add machine"
    echo "  2. python3 /opt/kite-agent/enroll.py --controller https://<controller> --token <token> --ca-fingerprint <sha256>"
    echo "  3. systemctl enable --now kite-agent"
    echo ""
    echo "  Or skip steps 2-3 next time by passing a token at install time:"
    echo "     sudo KITE_CONTROLLER=https://<controller> KITE_TOKEN=<token> dnf install -y kite-agent"
    echo "  Or, if the controller has a shared enrollment secret configured, skip the"
    echo "  per-host token entirely:"
    echo "     sudo KITE_CONTROLLER=https://<controller> KITE_SECRET=<shared-secret> dnf install -y kite-agent"
  fi
elif [ "$1" -ge 2 ] ; then
  # Upgrade — /etc/kite/agent.conf isn't part of this package (it's
  # generated at enroll time), so it survives untouched. Restart if the
  # service was already running so the new agent.py takes effect -- but
  # not when the agent itself is running this dnf (its self-update, or a
  # patch script): restarting the service stops everything it started,
  # this dnf included, partway through its transaction. The agent
  # restarts itself once its dnf has finished.
  if grep -q 'kite-agent\.service' /proc/self/cgroup 2>/dev/null; then
    :
  else
    systemctl try-restart kite-agent >/dev/null 2>&1 || true
  fi
  echo "kite-agent upgraded to %{version}-%{release}. Existing enrollment preserved."
fi

%preun
if [ "$1" -eq 0 ] ; then
  # Full removal (not an upgrade) — stop and disable before files disappear.
  systemctl stop kite-agent >/dev/null 2>&1 || true
  systemctl disable kite-agent >/dev/null 2>&1 || true
fi

%postun
if [ "$1" -eq 0 ] ; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

%changelog
* Tue Nov 03 2026 kite <kite@localhost> - 1.0.0-1
- First release.
