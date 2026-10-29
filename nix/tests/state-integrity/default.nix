{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "state-integrity";
  reason = "Corrupt PIN and credential MACs during operation and startup; require fail-closed errors and exact credential preservation after backup repair.";
  testScript = ''
    setup_migration()
    expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential login.example.test alice user-1 registration false")
    scenario("${./scenario.py}", timeout=90)
    machine.succeed("python3 ${../assert.py} /tmp/credential login.example.test repaired")
    assert mgmt("list --json").count('"local_id"') == 1
  '';
}
