{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-approval-lifecycle";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    env.scenario("${./scenario.py}", timeout=60)
    machine.succeed("systemctl stop tpm-passkey-test-agent; rm -f /run/user/1000/tpm-passkey-test-ready")
    machine.succeed("python3 ${./absent.py}", timeout=10)
    machine.succeed("systemctl start tpm-passkey-test-agent")
    env.wait_for_agent()
    machine.succeed("systemctl restart tpm-passkey")
    env.wait_for_agent()
    machine.succeed("fido2-manage -info -device 1")
  '';
}
