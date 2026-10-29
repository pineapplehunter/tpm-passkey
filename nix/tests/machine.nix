{ pkgs, package }:
{
  imports = [ ../nixos-module.nix ];

  virtualisation.tpm.enable = true;
  users.users.alice = {
    isNormalUser = true;
    uid = 1000;
    password = "alice";
    extraGroups = [ "tpm-passkey" ];
  };
  users.users.bob = {
    isNormalUser = true;
    uid = 1001;
    password = "bob";
  };
  services.tpm-passkey = {
    enable = true;
    package = package.daemon;
    cliPackage = package.cli;
    # Each scenario starts its own explicit test or real GTK agent.
    approval.enable = false;
    tpmPath = "/dev/tpm0";
    uhidPath = "/dev/uhid";
  };
  # The test-only agent controls the TTY fixture and advertises Wayland.
  # These protocol scenarios do not claim to test GTK UX.
  systemd.services.tpm-passkey-test-agent = {
    after = [ "tpm-passkey.service" ];
    serviceConfig = {
      User = "alice";
      ExecStart = "${pkgs.python3.withPackages (ps: [ ps.dbus-next ])}/bin/python3 ${./agent.py}";
      Restart = "on-failure";
      RestartSec = 1;
    };
    environment.XDG_RUNTIME_DIR = "/run/user/1000";
  };
  # Establish a login before starting the authenticator.
  systemd.services.tpm-passkey = {
    wantedBy = pkgs.lib.mkForce [ ];
    environment.RUST_LOG = "tpm_passkey=debug,sqlx=warn,zbus=warn";
  };
  environment.systemPackages = with pkgs; [
    fido2-manage
    expect
    tpm2-tools
    (python3.withPackages (ps: [
      ps.cbor2
      ps.fido2
      ps.dbus-next
    ]))
  ];
}
