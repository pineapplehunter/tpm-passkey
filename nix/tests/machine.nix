{ pkgs, package }:
{
  imports = [ ../nixos-module.nix ];

  virtualisation.tpm.enable = true;
  users.users.alice = {
    isNormalUser = true;
    password = "alice";
  };
  services.tpm-passkey = {
    enable = true;
    inherit package;
    tpmPath = "/dev/tpm0";
    uhidPath = "/dev/uhid";
  };
  # Establish a desktop subject before starting the authenticator.
  systemd.services.tpm-passkey = {
    wantedBy = pkgs.lib.mkForce [ ];
    environment.RUST_LOG = "tpm_passkey=debug,sqlx=warn,zbus=warn";
  };
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "io.github.pineapplehunter.tpm-passkey.approve"
          && subject.user == "alice") {
        return polkit.Result.YES;
      }
    });
  '';
  environment.systemPackages = with pkgs; [
    fido2-manage
    expect
    tpm2-tools
    (python3.withPackages (ps: [
      ps.cbor2
      ps.fido2
    ]))
  ];
}
