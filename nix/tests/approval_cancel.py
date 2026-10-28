"""Run while logind/polkit is SIGSTOP'd; CANCEL must release the CTAP worker."""
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID, CtapHidDevice


@contextlib.contextmanager
def monitor_polkit(enabled):
    if not enabled:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="approval-monitor-") as directory:
        directory = Path(directory)
        events = directory / "events.jsonl"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as ready, events.open("w") as output:
            path = str(directory / "notify")
            ready.bind(path)
            ready.settimeout(2)
            environment = dict(os.environ, NOTIFY_SOCKET=path)
            monitor = subprocess.Popen(
                ["busctl", "--system", "--json=short", "monitor", "org.freedesktop.PolicyKit1"],
                env=environment, stdout=output, stderr=subprocess.PIPE,
            )
            try:
                # busctl notifies only after BecomeMonitor has completed.
                assert b"READY=1" in ready.recv(1024)
                yield events
            finally:
                monitor.terminate()
                monitor.communicate(timeout=2)


def verify_server_cancellation(events):
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        rows = []
        for line in events.read_text().splitlines():
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # Last monitor record may still be being written.
        checks = [row for row in rows if row.get("member") == "CheckAuthorization"]
        cancels = [row for row in rows if row.get("member") == "CancelCheckAuthorization"]
        if checks and cancels:
            assert len(checks) == len(cancels) == 1
            assert checks[0]["sender"] == cancels[0]["sender"]
            pattern = r"tpm-passkey-\d+-\d+"
            check_ids = re.findall(pattern, json.dumps(checks[0]))
            cancel_ids = re.findall(pattern, json.dumps(cancels[0]))
            assert len(check_ids) == 1 and check_ids == cancel_ids
            return
        time.sleep(0.01)
    raise AssertionError("missing CheckAuthorization/CancelCheckAuthorization: " + events.read_text())


with monitor_polkit("--polkit" in sys.argv) as events:
    device = next(CtapHidDevice.list_devices())
    event = threading.Event()
    cancelled_at = None
    up_needed = threading.Event()

    def keepalive(status):
        if int(status) == 2:
            up_needed.set()

    def cancel_pending():
        global cancelled_at
        if not up_needed.wait(2):
            event.set()
            return
        if events is not None:
            # Wait until logind lookup has completed and the actual polkit
            # request is pending. Keepalive alone could precede that stage.
            deadline = time.monotonic() + 1.5
            while "CheckAuthorization" not in events.read_text():
                if time.monotonic() >= deadline:
                    event.set()
                    return
                time.sleep(0.01)
        cancelled_at = time.monotonic()
        event.set()

    watcher = threading.Thread(target=cancel_pending, daemon=True)
    watcher.start()
    watchdog = threading.Timer(4, event.set)
    watchdog.daemon = True
    watchdog.start()
    try:
        response = device.call(CTAPHID.CBOR, b"\x0b", event=event, on_keepalive=keepalive)
        assert cancelled_at is not None, "did not reach pending user-presence workflow"
        assert response == b"\x2d", response
        assert time.monotonic() - cancelled_at < 1, "CANCEL did not promptly free the worker"
        # This command must use the same worker successfully while the service
        # remains stopped; a transport-only response would not prove release.
        assert "FIDO_2_1" in Ctap2(device).info.versions
        if events is not None:
            verify_server_cancellation(events)
    finally:
        watchdog.cancel()
        device.close()
print("Pending approval cancelled; CTAP worker is responsive")
