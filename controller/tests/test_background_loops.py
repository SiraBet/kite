"""
The background loops share the server's event loop with every request.
A pass that waits on the network (Proxmox, a webhook, email) must run in
a thread, or the whole server stops answering until it's done.
"""
import asyncio
import time
from unittest.mock import patch

import pytest

from app import jobs_engine, monitoring, scheduler


@pytest.mark.parametrize("loop, slow_pass", [
    (monitoring.monitor_loop, "app.monitoring.detect_and_log_transitions"),
    (scheduler.scheduler_loop, "app.scheduler.run_scheduler_pass"),
    (jobs_engine.deferred_loop, "app.jobs_engine.complete_due_controller_stages"),
])
def test_a_slow_pass_does_not_stall_the_server(loop, slow_pass):
    def slow(*args, **kwargs):
        time.sleep(2)        # a slow network call, made the blocking way the passes make them
        return 0

    async def run():
        with patch(slow_pass, side_effect=slow):
            t = time.monotonic()
            task = asyncio.create_task(loop())
            await asyncio.sleep(0.05)   # stands in for answering a request while the pass runs
            waited = time.monotonic() - t
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return waited

    assert asyncio.run(run()) < 1   # blocked, it would be 2s or more
