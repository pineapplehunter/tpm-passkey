{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "approval-cancel";
  reason = "Cancel real UHID approval while logind is stalled or an agent dialog is pending; verify worker recovery and directed Cancel on the same sender/request ID.";
  testScript = ''
    machine.succeed("systemctl kill --kill-whom=main --signal=SIGSTOP systemd-logind.service")
    try:
        machine.succeed("python3 ${./cancel.py}", timeout=10)
    finally:
        machine.succeed("systemctl kill --kill-whom=main --signal=SIGCONT systemd-logind.service")
    wait_for_agent()
    machine.succeed("echo pending > /run/user/1000/tpm-passkey-test-mode")
    try:
        machine.succeed("python3 ${./cancel.py} --agent", timeout=10)
    finally:
        machine.succeed("rm -f /run/user/1000/tpm-passkey-test-mode")
  '';
}
