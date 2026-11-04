"""
app/proxmox_inventory.py: pages answer from the last fetch and never wait
on Proxmox (except the first fetch and an explicit Refresh); each
connection is fetched under its own lock; a failing one backs off.
"""
import threading
import time

import pytest
import requests

from app import proxmox, proxmox_inventory as inv

CFG_A = proxmox.ProxmoxConfig(host="pve-a.lab", node="pve", token_id="t@pve!a", token_secret="s")
CFG_B = proxmox.ProxmoxConfig(host="pve-b.lab", node="pve", token_id="t@pve!b", token_secret="s")
NODE = [{"type": "node", "node": "pve", "status": "online"}]


@pytest.fixture(autouse=True)
def _clean():
    inv.clear_cache()
    yield
    inv.clear_cache()


class FakeProxmox:
    def __init__(self, monkeypatch):
        self.calls, self.fail, self.delay = [], set(), {}
        monkeypatch.setattr(proxmox, "list_cluster_resources", self.list)

    def list(self, cfg):
        self.calls.append(cfg.host)
        time.sleep(self.delay.get(cfg.host, 0))
        if cfg.host in self.fail:
            raise requests.exceptions.ConnectTimeout("timed out")
        return [dict(NODE[0], at=len(self.calls))]


def _get(cfg, refresh=False):
    status = {}
    return inv._fetch(cfg, refresh, status), status


def _age(cfg, seconds):
    """Pretend the last attempt was `seconds` ago."""
    inv._entries[(cfg.host, cfg.token_id)].at -= seconds


def _settle():
    for t in threading.enumerate():
        if t.name.startswith("proxmox-inventory-"):
            t.join(5)


def test_the_first_fetch_waits_then_views_answer_from_it(monkeypatch):
    px = FakeProxmox(monkeypatch)
    rows, status = _get(CFG_A)
    assert rows and px.calls == ["pve-a.lab"] and not status.get("cached")
    rows, status = _get(CFG_A)
    assert px.calls == ["pve-a.lab"] and status["cached"] and not status["refreshing"]


def test_an_old_list_is_shown_at_once_and_refreshed_in_the_background(monkeypatch):
    px = FakeProxmox(monkeypatch)
    _get(CFG_A)
    _age(CFG_A, inv.CACHE_SECONDS + 1)
    px.delay["pve-a.lab"] = 0.5
    started = time.monotonic()
    rows, status = _get(CFG_A)
    assert time.monotonic() - started < 0.2, "the page waited on Proxmox"
    assert rows[0]["at"] == 1 and status["refreshing"]
    _get(CFG_A)                                  # a second view meanwhile doesn't start another fetch
    _settle()
    assert px.calls == ["pve-a.lab", "pve-a.lab"]
    rows, status = _get(CFG_A)
    assert rows[0]["at"] == 2 and not status["refreshing"]


def test_refresh_waits_for_a_new_fetch(monkeypatch):
    px = FakeProxmox(monkeypatch)
    _get(CFG_A)
    rows, status = _get(CFG_A, refresh=True)
    assert px.calls == ["pve-a.lab"] * 2 and rows[0]["at"] == 2


def test_a_proxmox_that_doesnt_answer_holds_up_no_other(monkeypatch):
    px = FakeProxmox(monkeypatch)
    _get(CFG_A)
    _get(CFG_B)
    px.delay["pve-a.lab"] = 1.0
    stuck = threading.Thread(target=_get, args=(CFG_A, True))   # someone pressed Refresh on a slow one
    stuck.start()
    time.sleep(0.1)
    started = time.monotonic()
    _get(CFG_B, refresh=True)
    _get(CFG_A)                                   # and the slow one's own page view answers from its last list
    assert time.monotonic() - started < 0.5
    stuck.join()


def test_a_failing_connection_backs_off(monkeypatch):
    px = FakeProxmox(monkeypatch)
    _get(CFG_A)
    px.fail.add("pve-a.lab")
    _get(CFG_A, refresh=True)                     # fails: 1 in a row
    rows, status = _get(CFG_A)
    assert rows and status["stale"] and "didn't answer" in status["error"]
    assert 0 < status["retry_in"] <= inv.RETRY_SECONDS[0] and not status["refreshing"]
    _age(CFG_A, 30)
    _get(CFG_A)
    assert px.calls.count("pve-a.lab") == 2       # not retried within the minute
    _age(CFG_A, inv.RETRY_SECONDS[0])
    _get(CFG_A)
    _settle()
    assert px.calls.count("pve-a.lab") == 3       # retried after it; 2 in a row now
    _age(CFG_A, inv.RETRY_SECONDS[0] + 1)
    _get(CFG_A)
    assert px.calls.count("pve-a.lab") == 3       # next wait is longer
    px.fail.clear()
    _age(CFG_A, inv.RETRY_SECONDS[1])
    _get(CFG_A)
    _settle()
    rows, status = _get(CFG_A)
    assert not status["error"] and status["retry_in"] is None and rows[0]["at"] == 4
