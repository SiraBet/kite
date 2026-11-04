"""
Operational logging, separate from the audit trail (see audit.py). The
audit log answers "who did what, to what" and is user-facing, queryable
via /audit. This is for the operator running `journalctl -u
kite-controller` or `docker compose logs` — system-health events
like a stuck stage or a host going offline, not user actions.

Plain text by default (readable directly in a terminal). JSON is opt-in
via KITE_LOG_FORMAT=json for anyone feeding this into a log
aggregator (Loki, ELK, CloudWatch) that wants structured fields instead
of parsing a text line.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from .config import settings


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging():
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_format == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())


logger = logging.getLogger("kite")
