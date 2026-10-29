# Shared NixOS test-driver helpers. Test-specific scenarios live in subdirectories.
import shlex


def login_alice():
    machine.send_key("ctrl-alt-f1")
    machine.wait_until_tty_matches("1", "login:", timeout=15)
    machine.send_chars("alice\n")
    machine.wait_until_tty_matches("1", "Password:", timeout=15)
    machine.send_chars("alice\n")
    machine.wait_until_tty_matches("1", "alice@", timeout=15)


def wait_for_agent():
    machine.wait_until_succeeds(
        'test -s /run/user/1000/tpm-passkey-test-ready && '
        'busctl --system call org.freedesktop.DBus /org/freedesktop/DBus '
        'org.freedesktop.DBus GetNameOwner s io.github.pineapplehunter.TpmPasskey1 '
        '| grep -Fq -- "\\\"$(cat /run/user/1000/tpm-passkey-test-ready)\\\""',
        timeout=15,
    )


def start_daemon():
    machine.succeed("systemctl start tpm-passkey")
    machine.wait_for_unit("tpm-passkey", timeout=15)
    machine.wait_until_succeeds(
        "python3 -c 'from fido2.hid import CtapHidDevice; from fido2.ctap2 import Ctap2; "
        "d = next(CtapHidDevice.list_devices()); assert Ctap2(d).info.versions; d.close()'",
        timeout=15,
    )
    machine.succeed("systemctl start tpm-passkey-test-agent")
    wait_for_agent()


def scenario(path, timeout=90):
    return machine.succeed(
        'PYTHONPATH=' + shlex.quote(python_helpers) + ' python3 ' + shlex.quote(path),
        timeout=timeout,
    )


def mgmt(command):
    return machine.succeed("tpm-passkey " + command)


def expect_command(command, script):
    body = (
        "set timeout 10; spawn " + command + "; expect_before timeout {exit 124}; " + script
        + "; set result [wait]; if {[lindex $result 2] != 0} {exit 1}; exit [lindex $result 3]"
    )
    return machine.succeed("expect -c " + shlex.quote(body), timeout=25)


def mgmt_expect(command, script):
    return expect_command("tpm-passkey " + command, script)


def setup_migration(passphrase="test migration phrase", pcr_indices=None):
    selection = " ".join(str(index) for index in (pcr_indices or []))
    return mgmt_expect(
        "setup",
        'expect "Choose PCR binding"; '
        f'send "{selection}\\r"; '
        'expect "Create migration passphrase: "; '
        f'send "{passphrase}\\r"; '
        'expect "Confirm passphrase: "; '
        f'send "{passphrase}\\r"; expect eof',
    )


def extend_pcr(digit):
    machine.succeed("tpm2_pcrextend 7:sha256=" + digit * 64)


def check_token_usage(expected):
    script = (
        'import sqlite3; '
        'db = sqlite3.connect("/var/lib/tpm-passkey/credentials.sqlite"); '
        'rows = db.execute("SELECT used_count, last_used FROM credential_tokens").fetchall(); '
        f'assert rows and all(count == {expected} and ((used is None) == ({expected} == 0)) '
        'for count, used in rows), rows'
    )
    machine.succeed("python3 -c " + shlex.quote(script))


machine.wait_for_unit("getty@tty1.service", timeout=60)
login_alice()
start_daemon()
