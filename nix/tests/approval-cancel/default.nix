{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "approval-cancel";
  reason = "Cancel a pending agent dialog; verify worker restart and directed Cancel on the same sender/request ID.";
  testScript = ''
    setup_migration()
    wait_for_agent()
    machine.succeed("echo pending > /run/user/1000/tpm-passkey-test-mode")
    try:
        machine.succeed("python3 ${./cancel.py} --agent", timeout=10)
    finally:
        machine.succeed("rm -f /run/user/1000/tpm-passkey-test-mode")
  '';
}
