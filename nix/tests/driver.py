# Shared NixOS test-driver helpers. Test-specific scenarios live in subdirectories.
import shlex


def login_alice():
    machine.send_key("ctrl-alt-f1")
    machine.wait_until_tty_matches("1", "login:", timeout=15)
    machine.send_chars("alice\n")
    machine.wait_until_tty_matches("1", "Password:", timeout=15)
    machine.send_chars("alice\n")
    machine.wait_until_tty_matches("1", "alice@", timeout=15)


def start_daemon():
    machine.succeed("systemctl start tpm-passkey")
    machine.wait_for_unit("tpm-passkey", timeout=15)


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


def set_recovery_phrase(new, old=""):
    return mgmt_expect(
        "config set recovery-passphrase",
        'expect "Enter current daemon passphrase (leave empty if not set yet): "; '
        f'send "{old}\\r"; '
        'expect "Enter new daemon passphrase: "; '
        f'send "{new}\\r"; expect eof',
    )


def recover(phrase, command="update-pcr-reference"):
    return mgmt_expect(
        command,
        f'expect "Enter recovery passphrase: "; send "{phrase}\\r"; expect eof',
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
