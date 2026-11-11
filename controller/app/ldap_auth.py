"""
Optional LDAP/Active Directory authentication — "search +
bind": first searches ldap_user_base_dn for an entry matching
ldap_user_filter (using a service account bind, or anonymously if
ldap_bind_dn is blank), then attempts a second bind as that entry's own
DN with the password the caller supplied. Only that second bind's
success/failure is what determines login — the search account never
needs to know or validate the user's password, and nothing from the
directory is trusted merely because an entry was found by the search.

Deliberately does NOT sync group membership to roles yet — every
LDAP-authenticated user is provisioned once (on first successful login)
with ldap_default_role, and an admin adjusts from there via
Settings -> Users (PATCH /users/{id}), same as any other role change. A
real group-to-role mapping is a reasonable follow-up, not built here.

The connection is always authenticated and encrypted unless an admin
turns that off: every password typed at the sign-in page travels over it,
and whoever can answer in the directory's place decides who gets in.
ldap3 on its own checks no certificate, and speaks plain LDAP to an
ldap:// address. So here an ldaps:// server must present a certificate
valid for its name, and an ldap:// server is upgraded with StartTLS, held
to the same check, before anything is sent. See _transport.
"""
import ssl

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from .settings_store import get_setting, get_secret

_CONNECT_TIMEOUT = 5
_RECEIVE_TIMEOUT = 5


def ldap_config(db) -> dict:
    return {
        "enabled": get_setting(db, "ldap_enabled") == "true",
        "server_uri": get_setting(db, "ldap_server_uri"),
        "bind_dn": get_setting(db, "ldap_bind_dn"),
        "bind_password": get_secret(db, "ldap_bind_password"),
        "user_base_dn": get_setting(db, "ldap_user_base_dn"),
        "user_filter": get_setting(db, "ldap_user_filter") or "(uid={username})",
        "default_role": get_setting(db, "ldap_default_role") or "operator",
        # Blank means on for both, like the other "safe unless switched off" settings.
        "verify_cert": get_setting(db, "ldap_verify_cert") != "false",
        "starttls": get_setting(db, "ldap_starttls") != "false",
        "ca_cert_file": get_setting(db, "ldap_ca_cert_file"),
    }


def _transport(cfg: dict):
    """
    (server, auto_bind) for the configured directory.

    The certificate is checked against ldap_ca_cert_file (a PEM file on the
    controller, for a directory with a private CA) or else the system's
    CAs, and against the host name in the address. ldap_verify_cert =
    "false" drops the check and keeps the encryption; ldap_starttls =
    "false" allows an ldap:// address to stay in clear text. Both are for a
    lab, and both are an admin's explicit choice.
    """
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED if cfg["verify_cert"] else ssl.CERT_NONE,
        ca_certs_file=cfg["ca_cert_file"] or None,
    )
    server = ldap3.Server(cfg["server_uri"], connect_timeout=_CONNECT_TIMEOUT, tls=tls)
    if server.ssl or not cfg["starttls"]:
        return server, True
    return server, ldap3.AUTO_BIND_TLS_BEFORE_BIND


def authenticate(db, username: str, password: str) -> bool:
    """
    True if username/password bind successfully against the configured
    directory. Never raises outward — any misconfiguration or connection
    problem is treated as "this login attempt failed" and reported to the
    caller the same as a wrong local password, so the client never learns
    whether a username exists, whether LDAP is even reachable, etc.
    """
    cfg = ldap_config(db)
    if not cfg["enabled"] or not cfg["server_uri"] or not cfg["user_base_dn"]:
        return False
    # ldap3 treats an empty password on a simple bind as an *anonymous*
    # bind, which most directories happily accept — that must never be
    # mistaken for "the password matched."
    if not password:
        return False

    try:
        server, auto_bind = _transport(cfg)
        search_conn = ldap3.Connection(
            server, user=(cfg["bind_dn"] or None), password=(cfg["bind_password"] or None),
            auto_bind=auto_bind, receive_timeout=_RECEIVE_TIMEOUT,
        )
        try:
            safe_username = escape_filter_chars(username)
            search_filter = cfg["user_filter"].format(username=safe_username)
            search_conn.search(cfg["user_base_dn"], search_filter, attributes=[])
            if len(search_conn.entries) != 1:
                return False  # not found, or ambiguous (matched more than one entry) — refuse either way
            user_dn = search_conn.entries[0].entry_dn
        finally:
            search_conn.unbind()

        user_conn = ldap3.Connection(server, user=user_dn, password=password,
                                      auto_bind=auto_bind, receive_timeout=_RECEIVE_TIMEOUT)
        user_conn.unbind()
        return True
    except LDAPException:
        return False
    except (KeyError, ValueError):
        return False  # a malformed ldap_user_filter (missing/bad '{username}' placeholder) — treat as a failed login, not a 500
