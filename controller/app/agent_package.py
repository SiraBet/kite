"""
Building a per-host Windows installer.

The console can hand out a setup binary that already knows which
controller it belongs to and carries a one-time enrollment token, so
installing on a host is a double-click with nothing to type and nothing
to mistype.

The configuration is appended after the end of the PE image. Windows
ignores trailing bytes -- the loader reads only what the headers
describe -- so the binary still runs.

    ... executable ...
    <json payload>
    <8 bytes: payload length, little-endian uint64>
    <16 bytes: MAGIC>

This is the writing half of a format whose reader is Go, in
agent-windows/internal/selfcfg. Both sides are deliberately trivial,
because anything cleverer would need the same cleverness implemented
twice and kept in step. The Go tests assert the magic is 16 bytes for
the same reason.

Two consequences worth stating. Appending invalidates an Authenticode
signature, so a generated installer cannot also be code signed -- sign
the generic download and accept that per-host builds are unsigned. And
the token sits in the file in clear text: it is single-use and expires,
so this is the same exposure as passing it on a command line, but the
file is a credential until it has been used.
"""
import json
import struct

MAGIC = b"KITE-CONFIG-v01\n"
assert len(MAGIC) == 16, "the format fixes the magic at 16 bytes; the Go reader assumes it"

LENGTH_STRUCT = struct.Struct("<Q")
MAX_PAYLOAD = 1 << 20


def build_footer(config: dict) -> bytes:
    """The bytes to append to an installer to configure it."""
    payload = json.dumps({k: v for k, v in config.items() if v not in (None, "", 0, False)},
                         separators=(",", ":")).encode()
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"embedded config is {len(payload)} bytes, over the {MAX_PAYLOAD} limit")
    return payload + LENGTH_STRUCT.pack(len(payload)) + MAGIC


def strip_footer(body: bytes) -> bytes:
    """
    Remove an existing footer if there is one, so regenerating from an
    already-generated binary replaces the configuration rather than
    stacking a second copy behind it.
    """
    trailer = LENGTH_STRUCT.size + len(MAGIC)
    if len(body) < trailer or body[-len(MAGIC):] != MAGIC:
        return body
    (length,) = LENGTH_STRUCT.unpack(body[-trailer:-len(MAGIC)])
    cut = len(body) - trailer - length
    return body if cut < 0 else body[:cut]


def configure(installer: bytes, config: dict) -> bytes:
    """A copy of `installer` carrying `config`."""
    return strip_footer(installer) + build_footer(config)


def read_footer(body: bytes):
    """
    The configuration in a built installer, or None. Only used by the
    tests -- the agent reads its own footer in Go -- but a format with a
    writer and no reader on this side is a format nothing here can check.
    """
    trailer = LENGTH_STRUCT.size + len(MAGIC)
    if len(body) < trailer or body[-len(MAGIC):] != MAGIC:
        return None
    (length,) = LENGTH_STRUCT.unpack(body[-trailer:-len(MAGIC)])
    if length == 0 or length > MAX_PAYLOAD or length + trailer > len(body):
        return None
    payload = body[-trailer - length:-trailer]
    try:
        return json.loads(payload)
    except ValueError:
        return None
