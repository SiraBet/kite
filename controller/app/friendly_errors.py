"""
What the console says when something kite talks to -- Proxmox, a
vulnerability source -- fails.

A raw exception ("HTTPSConnectionPool(host=..., port=8006): Max retries
exceeded ... ConnectTimeoutError(<HTTPSConnection ...>)") says little
to the person reading it and shows internals they don't need. describe()
turns one into a short sentence that names the problem and the next
step; the exception itself goes to the controller's log, for whoever
needs the detail.
"""
import re
import socket

import requests

from .logging_config import logger

_STATUS = re.compile(r"\((\d{3})\)")


def _status(exc) -> int:
    """The HTTP status in an error: a response's, or the '(401)' our own errors carry."""
    resp = getattr(exc, "response", None)
    if resp is not None and getattr(resp, "status_code", None):
        return resp.status_code
    m = _STATUS.search(str(exc))
    return int(m.group(1)) if m else 0


LOCAL = "Check it's switched on and reachable from the controller."
INTERNET = "Check the controller can reach the internet (firewall, proxy)."


def describe(exc, what="Proxmox", token_hint="Check the API token and its permissions in Settings → Connections.",
             reach_hint=LOCAL) -> str:
    """
    A short, plain sentence about `exc` for the console. Doesn't log: see
    report(). `reach_hint` is the next step when it can't be reached at
    all: LOCAL for a machine on the network, INTERNET for an online service.
    """
    from . import proxmox  # local: proxmox imports nothing from here, but keep the dependency one way

    text = str(exc)
    if isinstance(exc, proxmox.ProxmoxTaskFailed):
        return text   # Proxmox's own short reason: "Proxmox task failed: <why>"
    if isinstance(exc, (requests.exceptions.Timeout, socket.timeout, TimeoutError)) or "timed out" in text:
        return f"{what} didn't answer in time. {reach_hint}"
    if isinstance(exc, requests.exceptions.SSLError) or "CERTIFICATE_VERIFY_FAILED" in text:
        return (f"{what}'s certificate isn't trusted. A default Proxmox certificate is self-signed: leave "
                "'Verify TLS certificate' off for it, or install one this controller trusts."
                if what == "Proxmox" or what.endswith("Proxmox") else
                f"{what}'s certificate isn't trusted by this controller.")
    if isinstance(exc, (requests.exceptions.ConnectionError, ConnectionError, OSError)) and not _status(exc):
        if "refused" in text.lower():
            return f"{what} refused the connection. Check the address and port."
        if any(s in text for s in ("Name or service not known", "NameResolution", "getaddrinfo",
                                   "nodename nor servname", "Temporary failure in name resolution")):
            return f"Couldn't find {what}'s address. Check the host name."
        if "unreachable" in text.lower() or "No route to host" in text:
            return f"There's no network route from the controller to {what}."
        return f"Couldn't connect to {what}. {reach_hint}"
    status = _status(exc)
    if status == 401:
        return f"{what} didn't accept the credentials. {token_hint}".strip()
    if status == 403:
        return f"{what} refused the request (not allowed). {token_hint}".strip()
    if status == 404:
        return f"{what} says it doesn't have that (not found)."
    if status in (595, 596):
        return f"{what} couldn't reach one of its own nodes. Check the cluster in {what}."
    if status >= 500:
        return f"{what} had an internal error (HTTP {status}). Its own logs say why."
    if status:
        return f"{what} answered with an error (HTTP {status})."
    if isinstance(exc, (proxmox.ProxmoxError, RuntimeError)) and "\n" not in text and len(text) < 300 \
            and "Pool(" not in text and "object at 0x" not in text:
        return text   # our own message: already written for people
    return f"Something went wrong talking to {what}. The controller's log has the details."


def report(exc, what="Proxmox", context="", **kw) -> str:
    """describe(), and the full exception into the log."""
    logger.warning("%s%s: %s", f"{context}: " if context else "", what, exc)
    return describe(exc, what, **kw)
