{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "migration-upgrade";
  reason = "Upgrade a pre-redesign database: discard credentials and old configuration, retain the exact real client PIN, require fresh migration setup, and enroll with the retained PIN.";
  testScript = ''
    expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    machine.succeed("systemctl stop tpm-passkey")
    machine.succeed("python3 ${./legacy.py} prepare ${../../../migrations}")
    start_daemon()
    machine.succeed("python3 ${./legacy.py} check")
    assert mgmt("list --json").strip() == "[]"
    assert "false" in mgmt("config show")
    machine.succeed("mkdir -p /tmp/upgrade-credential")
    register = "python3 ${../register.py} /tmp/upgrade-credential upgrade.example.test alice user-1 registration true 1234"
    machine.fail(register)
    setup_migration("fresh upgrade migration phrase")
    machine.succeed(register)
    machine.succeed("python3 ${../assert.py} /tmp/upgrade-credential upgrade.example.test retained-pin")
  '';
}
