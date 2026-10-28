{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "approval-cancel";
  reason = "Stop real logind/polkit during approval, cancel over UHID, and verify prompt worker recovery plus the polkit cancellation sender/ID.";
  testScript = ''
    machine.wait_for_unit("polkit.service", timeout=15)
    for unit, arguments in [("systemd-logind.service", ""), ("polkit.service", "--polkit")]:
        machine.succeed(f"systemctl kill --kill-whom=main --signal=SIGSTOP {unit}")
        try:
            machine.succeed("python3 ${./cancel.py} " + arguments, timeout=10)
        finally:
            machine.succeed(f"systemctl kill --kill-whom=main --signal=SIGCONT {unit}")
  '';
}
