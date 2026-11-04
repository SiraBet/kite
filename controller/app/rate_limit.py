"""
Shared Limiter instance — needs its own module (not defined in main.py)
so routers can import it without a circular import back to main.
"""
import ipaddress
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# Which immediate peers are allowed to speak for a client via
# X-Forwarded-For. This is deployment-dependent and MUST match reality:
# an X-Forwarded-For header is only trustworthy when the TCP peer we
# actually received the request from is a proxy we run. Defaults to
# loopback, because the documented deployment puts Caddy on the same host
# in front of uvicorn. Override with KITE_TRUSTED_PROXIES (comma-
# separated peer IPs or networks, e.g. 10.0.0.5 or 10.89.0.0/24) when the
# proxy is elsewhere -- in Docker Compose, Caddy's own container (see
# docker-compose.yml).
def _parse(spec: str):
    """(networks, other names) -- a peer that isn't an IP (a test client) can only match by name."""
    nets, names = [], set()
    for p in (x.strip() for x in spec.split(",")):
        if not p:
            continue
        try:
            nets.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            names.add(p)
    return nets, names


_TRUSTED_NETS, _TRUSTED_NAMES = _parse(os.environ.get("KITE_TRUSTED_PROXIES", "127.0.0.1,::1"))


def _trusted(peer: str) -> bool:
    if peer in _TRUSTED_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(ip in net for net in _TRUSTED_NETS)


def _rate_limit_key(request):
    """
    The per-IP rate-limit bucket key.

    X-Forwarded-For is honored ONLY when the request's immediate peer is
    a configured trusted proxy (see _TRUSTED_PROXIES). Behind the
    documented Caddy front-end that peer is loopback, and Caddy (like any
    standard reverse proxy) APPENDS the real client IP to whatever the
    client may already have sent — so the entry Caddy itself added is the
    LAST one, and that is the entry we read. A client can freely set the
    earlier entries; reading the first (as an earlier version did) let
    the limiter be bypassed by rotating a spoofed first entry, verified
    live as 10/10 rapid /auth/login attempts passing with no 429.

    When the peer is NOT a trusted proxy — e.g. this process is exposed
    directly on the network with no proxy in front, which is exactly when
    a client can spoof the header — X-Forwarded-For is ignored entirely
    and the real socket peer is used. Trusting it there would hand every
    client its own rate-limit-bypass knob.
    """
    peer = get_remote_address(request)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _trusted(peer):
        return forwarded.split(",")[-1].strip()
    return peer


limiter = Limiter(key_func=_rate_limit_key)
