{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-gtk-approval";
  nodes.machine = {
    imports = [ (import ../machine.nix { inherit pkgs package; }) ];
    environment.systemPackages = [
      package.gtk
      pkgs.xdotool
    ];
    systemd.services.tpm-passkey-test-xvfb.serviceConfig = {
      User = "alice";
      ExecStart = "${pkgs.xvfb}/bin/Xvfb :99 -screen 0 1024x768x24 -nolisten tcp -ac";
    };
    systemd.services.tpm-passkey-test-session = {
      serviceConfig = {
        User = "alice";
        ExecStart = "${
          pkgs.python3.withPackages (ps: [ ps.dbus-next ])
        }/bin/python3 ${../agent.py} --session-only --x11";
      };
      environment.XDG_RUNTIME_DIR = "/run/user/1000";
    };
    systemd.services.tpm-passkey-test-gtk = {
      serviceConfig = {
        User = "alice";
        ExecStart = pkgs.lib.getExe package.gtk;
      };
      environment = {
        DISPLAY = ":99";
        GDK_BACKEND = "x11";
        XDG_RUNTIME_DIR = "/run/user/1000";
        DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus";
      };
    };
  };
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    machine.succeed("systemctl stop tpm-passkey-test-agent")
    machine.succeed("systemctl start tpm-passkey-test-session tpm-passkey-test-xvfb")
    machine.wait_until_succeeds("test -S /tmp/.X11-unix/X99", timeout=15)
    machine.succeed("systemctl start tpm-passkey-test-gtk")
    machine.wait_for_unit("tpm-passkey-test-gtk", timeout=15)
    machine.wait_until_succeeds("journalctl -u tpm-passkey-test-gtk --no-pager | grep -i registered", timeout=15)
    machine.succeed("mkdir -p /tmp/gtk-registration; python3 ${../register.py} /tmp/gtk-registration gtk-smoke.example.test alice user-gtk registration false > /tmp/gtk-result 2>&1 & echo $! > /tmp/gtk-client-pid")
    search = "DISPLAY=:99 xdotool search --onlyvisible --pid $(systemctl show tpm-passkey-test-gtk -p MainPID --value)"
    machine.wait_until_succeeds(search, timeout=15)
    window = machine.succeed(search).strip().splitlines()[0]
    # Explicit focus for synthetic X11 input; do not imply Wayland focus guarantees.
    machine.succeed(f"DISPLAY=:99 xdotool windowfocus {window} key Escape")
    machine.wait_until_succeeds("! kill -0 $(cat /tmp/gtk-client-pid)", timeout=10)
    assert "OPERATION_DENIED" in machine.succeed("cat /tmp/gtk-result")
    assert env.mgmt("list --json").strip() == "[]"
    machine.succeed("test $(systemctl show tpm-passkey-test-gtk -p User --value) = alice")
  '';
}
