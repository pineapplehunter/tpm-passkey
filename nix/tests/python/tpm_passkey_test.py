"""Shared VM-driver helpers for the tpm-passkey NixOS tests."""
import shlex


class TestEnv:
    def __init__(self, machine):
        self.machine = machine

    def start(self):
        self.machine.wait_for_unit("getty@tty1.service", timeout=60)
        self.login_alice()
        self.start_daemon()

    def login_alice(self):
        self.machine.send_key("ctrl-alt-f1")
        self.machine.wait_until_tty_matches("1", "login:", timeout=60)
        self.machine.send_chars("alice\n")
        self.machine.wait_until_tty_matches("1", "Password:", timeout=60)
        self.machine.send_chars("alice\n")
        self.machine.wait_until_tty_matches("1", "alice@", timeout=60)

    def wait_for_agent(self):
        self.machine.wait_until_succeeds(
            'test -s /run/user/1000/tpm-passkey-test-ready && '
            'busctl --system call org.freedesktop.DBus /org/freedesktop/DBus '
            'org.freedesktop.DBus GetNameOwner s io.github.pineapplehunter.TpmPasskey1 '
            '| grep -Fq -- "\\\"$(cat /run/user/1000/tpm-passkey-test-ready)\\\""',
            timeout=15,
        )

    def start_daemon(self):
        self.machine.succeed("systemctl start tpm-passkey")
        self.machine.wait_for_unit("tpm-passkey", timeout=15)
        self.machine.wait_until_succeeds(
            "python3 -c 'from fido2.hid import CtapHidDevice; from fido2.ctap2 import Ctap2; "
            "d = next(CtapHidDevice.list_devices()); assert Ctap2(d).info.versions; d.close()'",
            timeout=15,
        )
        self.machine.succeed("systemctl start tpm-passkey-test-agent")
        self.wait_for_agent()

    def scenario(self, path, timeout=90):
        return self.machine.succeed('python3 ' + shlex.quote(path), timeout=timeout)

    def mgmt(self, command):
        return self.machine.succeed("tpm-passkey " + command)

    def expect_command(self, command, script):
        body = (
            "set timeout 10; spawn " + command + "; expect_before timeout {exit 124}; " + script
            + "; set result [wait]; if {[lindex $result 2] != 0} {exit 1}; exit [lindex $result 3]"
        )
        return self.machine.succeed("expect -c " + shlex.quote(body), timeout=25)

    def mgmt_expect(self, command, script):
        return self.expect_command("tpm-passkey " + command, script)

    def setup_migration(self, passphrase="test migration phrase", pcr_indices=None):
        selection = " ".join(str(index) for index in (pcr_indices or []))
        return self.mgmt_expect(
            "setup",
            'expect "Choose PCR binding"; '
            f'send "{selection}\\r"; '
            'expect "Create migration passphrase: "; '
            f'send "{passphrase}\\r"; '
            'expect "Confirm passphrase: "; '
            f'send "{passphrase}\\r"; expect eof',
        )

    def extend_pcr(self, digit):
        self.machine.succeed("tpm2_pcrextend 7:sha256=" + digit * 64)

    def check_token_usage(self, expected):
        script = (
            'import sqlite3; '
            'db = sqlite3.connect("/var/lib/tpm-passkey/credentials.sqlite"); '
            'rows = db.execute("SELECT used_count, last_used FROM credential_tokens").fetchall(); '
            f'assert rows and all(count == {expected} and ((used is None) == ({expected} == 0)) '
            'for count, used in rows), rows'
        )
        self.machine.succeed("python3 -c " + shlex.quote(script))
