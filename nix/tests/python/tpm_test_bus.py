"""Shared test-only management transport and registered-agent readiness helpers."""
import asyncio
import fcntl
import os
from pathlib import Path
import subprocess
import time

import cbor2
from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus

NAME = "io.github.pineapplehunter.TpmPasskey1"
PATH = "/io/github/pineapplehunter/TpmPasskey1"
IFACE = NAME


async def call(bus, destination, path, interface, member, signature='', body=None, unix_fds=None):
    reply = await asyncio.wait_for(bus.call(Message(destination=destination, path=path,
        interface=interface, member=member, signature=signature, body=body or [],
        unix_fds=unix_fds or [])), 40)
    if reply.message_type == MessageType.ERROR:
        raise RuntimeError(reply.error_name)
    return reply.body


async def manage_raw(operation, encoded, sealed=True):
    bus = await MessageBus(bus_type=BusType.SYSTEM, negotiate_unix_fd=True).connect()
    fd = os.memfd_create("tpm-passkey-test-request", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, encoded)
        if sealed:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        owner = (await call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetNameOwner", 's', [NAME]))[0]
        assert (await call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetConnectionUnixUser", 's', [owner])) == [0]
        reply = await call(bus, owner, PATH, IFACE, "Manage", 'sh', [operation, 0], [fd])
        return cbor2.loads(reply[0])
    finally:
        os.close(fd)
        bus.disconnect()


def management(command, params=None, ok=True):
    request = command if params is None else {command: params}
    response = asyncio.run(manage_raw(command, cbor2.dumps(request)))
    assert response["ok"] == ok, response
    return response.get("result")


def wait_for_agent():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            owner = subprocess.check_output([
                "busctl", "--system", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", "GetNameOwner", "s", NAME], text=True).split('"')[1]
            if Path("/run/user/1000/tpm-passkey-test-ready").read_text() == owner:
                return
        except (OSError, subprocess.CalledProcessError, IndexError):
            pass
        time.sleep(0.02)
    raise AssertionError("approval agent did not register with current daemon")
