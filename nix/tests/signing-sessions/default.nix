{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-signing-sessions";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.mgmt_expect(
        "setup",
        'expect "Choose PCR binding"; send "7\\r"; '
        'expect "Create migration passphrase: "; send "signing-session-phrase\\r"; '
        'expect "Confirm passphrase: "; send "signing-session-phrase\\r"; expect eof',
    )
    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential sessions.example.test alice user-1 registration false")
    for _ in range(20):
        machine.succeed("python3 ${../assert.py} /tmp/credential sessions.example.test assertion")
  '';
}
