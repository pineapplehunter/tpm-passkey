{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-pin-management";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    env.expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    for user in ["first", "second"]:
        machine.succeed(f"mkdir -p /tmp/{user}")
        machine.succeed(f"python3 ${../register.py} /tmp/{user} pin.example.test {user} {user} registration true 1234")
    env.expect_command("fido2-manage -storage -device 1",
        'expect "Enter PIN"; send "1234\\r"; expect eof')
    env.expect_command("fido2-manage -changePIN -device 1",
        'expect "Enter current PIN"; send "1234\\r"; '
        'expect "Enter new PIN"; send "5678\\r"; '
        'expect "Enter the same PIN again"; send "5678\\r"; expect eof')
    first = machine.succeed("python3 -c 'import base64,sqlite3; db=sqlite3.connect(\"/var/lib/tpm-passkey/credentials.sqlite\"); print(base64.b64encode(db.execute(\"SELECT credential_id FROM credential_metadata WHERE user_name=\\\"first\\\"\").fetchone()[0]).decode())'").strip()
    env.expect_command(f"fido2-manage -delete -device 1 -credential {first}",
        'expect "Are you sure you want to proceed?"; send "Y\\r"; '
        'expect "Enter PIN"; send "5678\\r"; expect eof')
    assert env.mgmt("list --json").count('"local_id"') == 1
    machine.fail("python3 ${../assert.py} /tmp/first pin.example.test deleted")
    machine.succeed("python3 ${../assert.py} /tmp/second pin.example.test retained")

  '';
}
