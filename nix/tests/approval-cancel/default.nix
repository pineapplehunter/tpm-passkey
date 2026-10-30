{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-approval-cancel";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    env.wait_for_agent()
    machine.succeed("echo pending > /run/user/1000/tpm-passkey-test-mode")
    try:
        machine.succeed("python3 ${./cancel.py} --agent", timeout=10)
    finally:
        machine.succeed("rm -f /run/user/1000/tpm-passkey-test-mode")
  '';
}
