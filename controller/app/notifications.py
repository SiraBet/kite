"""
Outbound notifications. Every notable system event already
flows through audit.log() -- stage failures, a host going offline, a
stuck stage, a schedule skipped for a missing/unapproved ticket, a run
completing -- so this hooks in there instead of sprinkling notify()
calls through jobs_engine.py/monitoring.py/scheduler.py individually,
which would be easy to miss a call site on.

Three channels, all optional and independently configured (Settings ->
Notifications): a generic webhook (POST JSON, works with anything,
including a Teams "when a webhook is received" Power Automate flow --
Teams' own legacy Office 365 Connector webhooks are being retired
vendor-side as of this writing, so this project isn't chasing that
moving target with bespoke Teams code), a Slack-compatible incoming
webhook, and email via plain SMTP (stdlib smtplib, no new dependency).

Delivery is synchronous, inline, with a short timeout and a broad
except -- a notification failure (unreachable webhook, bad SMTP creds)
must never break the underlying operation it's reporting on, same
"best-effort, never breaks the real thing" principle already used for
Proxmox VMID auto-resolution. No queue, no retry, no delivery guarantee
-- if the channel is down when this fires, that notification is just
gone. A real message queue is more infrastructure than this project's
scope justifies right now.
"""
import ipaddress
import smtplib
import socket
import ssl
from email.mime.text import MIMEText
from urllib.parse import urlparse

import requests

from .logging_config import logger
from .settings_store import get_setting, get_secret

WEBHOOK_TIMEOUT = 5


def _webhook_url_is_blocked(url: str) -> bool:
    """
    An admin-configured webhook URL that this process itself fetches is a
    textbook SSRF vector: point it at http://169.254.169.254/... (cloud
    instance metadata -- the highest-value SSRF target there is) or at
    the controller's own loopback and this becomes an internal-network
    proxy for whoever can set it.

    Deliberately NOT blocking ordinary RFC1918/private ranges, though --
    unlike a multi-tenant SaaS, kite's whole deployment model is "on
    a private network" (see INSTALL.md), so a self-hosted webhook
    receiver on the same LAN (a local ntfy/Mattermost/etc.) is a real,
    intended use case, not an attack. This blocks the specific ranges
    that are never a legitimate webhook destination for anyone: loopback,
    link-local (covers the AWS/GCP/Azure/Oracle metadata address, since
    169.254.0.0/16 is link-local), unspecified, and multicast.

    Resolve-then-check like this doesn't close a DNS-rebinding TOCTOU
    (the name could re-resolve differently between this check and the
    actual request) -- not attempting that here, since the realistic
    attacker in this threat model is the admin setting the URL, who
    doesn't need rebinding tricks against their own webhook config.
    """
    host = urlparse(url).hostname
    if not host:
        return True  # unparseable / no host at all -- fail closed
    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # doesn't resolve -- fail closed rather than let requests try again later
    for info in resolved:
        ip = ipaddress.ip_address(info[4][0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # catches ::ffff:169.254.169.254-style IPv4-in-IPv6 tricks
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return True
    return False

# The "something needs a human" set -- always notified if any channel is
# configured. run_completed is opt-in separately (notify_on_success,
# default off) since a success message per host per run is noise at
# fleet scale for most people, even though the roadmap explicitly asked
# for job completion as an available trigger -- it's available, just
# not the default.
# batch_paused: a rollout stopped on a failure and is waiting for a person,
# who for a scheduled one isn't watching.
ALWAYS_NOTIFY_ACTIONS = {"stage_failed", "host_offline", "stage_stuck", "schedule_skipped",
                          "critical_update_found", "port_opened", "batch_paused", "run_expired"}
OPT_IN_SUCCESS_ACTIONS = {"run_completed"}

_TONE_EMOJI = {"danger": "🔴", "warning": "🟡", "success": "✅"}


def notify_if_relevant(db, action: str, detail: str, tone: str):
    if action not in ALWAYS_NOTIFY_ACTIONS:
        if action not in OPT_IN_SUCCESS_ACTIONS or get_setting(db, "notify_on_success") != "true":
            return
    _send_generic_webhook(db, action, detail, tone)
    _send_slack(db, action, detail, tone)
    _send_email(db, action, detail)


def _where(url: str) -> str:
    """
    A webhook's host, for log lines. Never the URL: for Slack and most
    receivers the path is the credential, and these lines go to the
    journal (and on from there), which is not where a secret kept
    encrypted in the database should end up.
    """
    return urlparse(url).hostname or "an unreadable address"


def _post_webhook(url: str, body: dict, what: str):
    """
    Not following redirects: _webhook_url_is_blocked vetted the address
    in the setting, and a receiver answering "302, try
    http://169.254.169.254/..." would send the request on to exactly the
    place that check exists to keep it away from.
    """
    try:
        resp = requests.post(url, json=body, timeout=WEBHOOK_TIMEOUT, allow_redirects=False)
        if resp.is_redirect:
            logger.warning("%s notification not delivered: %s answered with a redirect, which isn't followed",
                           what, _where(url))
    except requests.RequestException as e:
        # The exception's text carries the full URL too.
        logger.warning("%s notification to %s failed: %s", what, _where(url), type(e).__name__)


def _send_generic_webhook(db, action, detail, tone):
    url = get_secret(db, "notify_generic_webhook")
    if not url:
        return
    if _webhook_url_is_blocked(url):
        logger.warning("generic webhook notification skipped: %s resolves to a blocked address", _where(url))
        return
    _post_webhook(url, {"action": action, "detail": detail, "tone": tone}, "generic webhook")


def _send_slack(db, action, detail, tone):
    url = get_secret(db, "notify_slack_webhook")
    if not url:
        return
    if _webhook_url_is_blocked(url):
        logger.warning("Slack notification skipped: %s resolves to a blocked address", _where(url))
        return
    emoji = _TONE_EMOJI.get(tone, "ℹ️")
    _post_webhook(url, {"text": f"{emoji} *kite* — {action}: {detail}"}, "Slack")


def _send_email(db, action, detail):
    host = get_setting(db, "notify_smtp_host")
    to = get_setting(db, "notify_smtp_to")
    if not host or not to:
        return
    try:
        port = int(get_setting(db, "notify_smtp_port") or "587")
    except ValueError:
        # Every audit entry passes through here. A port that isn't a
        # number must cost this one email, not raise into whatever was
        # being logged -- a failed stage, a batch moving on.
        logger.warning("email notification skipped: notify_smtp_port %r is not a number",
                       get_setting(db, "notify_smtp_port"))
        return
    username = get_setting(db, "notify_smtp_username")
    password = get_secret(db, "notify_smtp_password")
    from_addr = get_setting(db, "notify_smtp_from") or username or "kite@localhost"
    use_tls = get_setting(db, "notify_smtp_use_tls") != "false"
    verify_cert = get_setting(db, "notify_smtp_verify_cert") != "false"
    recipients = [r.strip() for r in to.split(",") if r.strip()]

    msg = MIMEText(detail)
    msg["Subject"] = f"[kite] {action}"
    msg["From"] = from_addr
    msg["To"] = to

    try:
        with smtplib.SMTP(host, port, timeout=WEBHOOK_TIMEOUT) as server:
            if use_tls:
                # smtplib's own default context checks neither the
                # certificate nor the host name, which would hand the
                # login below to anyone able to answer for this server.
                context = ssl.create_default_context()
                if not verify_cert:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, recipients, msg.as_string())
    except Exception as e:  # noqa: BLE001 -- smtplib raises several distinct exception types; catch broadly, same as the other two channels above
        logger.warning("email notification failed: %s", e)
