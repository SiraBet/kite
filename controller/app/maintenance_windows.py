"""
A ticket's approved maintenance window — the hours a run is allowed to
start. Nothing to do with the Windows agent in agent-windows/, which is
why this module isn't just called `windows`.
"""
from datetime import datetime


def within_window(ticket, now: datetime = None) -> bool:
    """
    Inclusive on both ends, in UTC. A window whose end hour is less than
    its start (e.g. 22 -> 04) wraps past midnight rather than being empty.
    """
    now = now or datetime.utcnow()
    hour = now.hour
    start, end = ticket.window_start, ticket.window_end
    return (hour >= start and hour <= end) if start <= end else (hour >= start or hour <= end)
