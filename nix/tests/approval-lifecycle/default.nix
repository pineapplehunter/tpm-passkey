{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "approval-lifecycle";
  reason = "Exercise fresh Allow/Deny and absent helper; no cached consent may survive.";
  testScript = ''
    scenario("${./scenario.py}", timeout=60)
    machine.succeed("systemctl stop tpm-passkey-test-agent; rm -f /run/user/1000/tpm-passkey-test-ready")
    machine.succeed("python3 ${./absent.py}", timeout=10)
    machine.succeed("systemctl start tpm-passkey-test-agent")
    wait_for_agent()
    machine.succeed("systemctl restart tpm-passkey")
    wait_for_agent()
    machine.succeed("fido2-manage -info -device 1")
  '';
}
