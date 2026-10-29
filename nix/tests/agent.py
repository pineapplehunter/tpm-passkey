"""Test-only system-bus agent; NOT shipped with production binaries.

The login fixture is a TTY with a simulated Wayland session. This is not
evidence of GTK UX. The dedicated GTK test runs the real GUI separately.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method

NAME = "io.github.pineapplehunter.TpmPasskey1"
PATH = "/io/github/pineapplehunter/TpmPasskey1"
IFACE = NAME
AGENT_PATH = PATH + "/ApprovalAgent"
AGENT_IFACE = NAME + ".ApprovalAgent"
ROOT = Path(os.environ["XDG_RUNTIME_DIR"])
READY = ROOT / "tpm-passkey-test-ready"
MODE = ROOT / "tpm-passkey-test-mode"
EVENTS = ROOT / "tpm-passkey-test-events"


def record(kind, **fields):
    with EVENTS.open("a") as output:
        output.write(json.dumps(dict(kind=kind, **fields)) + "\n")


class Agent(ServiceInterface):
    def __init__(self):
        super().__init__(AGENT_IFACE)
        self.pending = {}

    @method()
    async def Request(self, request_id: 's', context: '(sssssu)', timeout_ms: 'u') -> 'b':
        record("request", id=request_id, context=context)
        if self.pending:
            return False
        cancel = asyncio.Event()
        self.pending[request_id] = cancel
        try:
            deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
            while asyncio.get_running_loop().time() < deadline:
                if cancel.is_set():
                    return False
                mode = MODE.read_text().strip() if MODE.exists() else "allow"
                if mode == "allow":
                    return True
                if mode == "deny":
                    return False
                await asyncio.sleep(0.01)
            return False
        finally:
            self.pending.pop(request_id, None)

    @method()
    def Cancel(self, request_id: 's'):
        record("cancel", id=request_id)
        if request_id in self.pending:
            self.pending[request_id].set()


async def call(bus, destination, path, interface, member, signature='', body=None):
    reply = await asyncio.wait_for(bus.call(Message(destination=destination, path=path,
        interface=interface, member=member, signature=signature, body=body or [])), 3)
    if reply.message_type == MessageType.ERROR:
        raise RuntimeError(reply.error_name)
    return reply.body


async def main():
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    sessions = (await call(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "ListSessions"))[0]
    matches = [row for row in sessions if row[1] == os.getuid() and row[3]]
    assert len(matches) == 1, matches
    session = matches[0][4]
    await call(bus, "org.freedesktop.login1", session,
        "org.freedesktop.login1.Session", "TakeControl", 'b', [False])
    await call(bus, "org.freedesktop.login1", session,
        "org.freedesktop.login1.Session", "SetType", 's', ["x11" if "--x11" in sys.argv else "wayland"])
    if "--session-only" in sys.argv:
        await asyncio.Event().wait()
        return
    agent = Agent()
    def observe(message):
        if message.interface == AGENT_IFACE and message.member in ("Request", "Cancel"):
            record("wire", member=message.member, id=message.body[0], sender=message.sender)
    bus.add_message_handler(observe)
    bus.export(AGENT_PATH, agent)
    owner = None
    while True:
        current = None
        try:
            current = (await call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", "GetNameOwner", 's', [NAME]))[0]
            if owner != current:
                READY.unlink(missing_ok=True)
                for event in agent.pending.values():
                    event.set()
            if not agent.pending:
                await call(bus, current, PATH, IFACE, "RegisterAgent", 'o', [AGENT_PATH])
                owner = current
                READY.write_text(owner)
        except (RuntimeError, asyncio.TimeoutError):
            READY.unlink(missing_ok=True)
            # Registration may race the start of a request and be rejected as
            # busy. That is not daemon loss and must not cancel the new request.
            if current is None:
                owner = None
                for event in agent.pending.values():
                    event.set()
            else:
                owner = current
        await asyncio.sleep(0.1)


asyncio.run(main())
