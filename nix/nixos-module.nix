{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    types
    mkIf
    mkEnableOption
    mkOption
    ;
  cfg = config.services.tpm-passkey;
in
{
  options.services.tpm-passkey = {
    enable = mkEnableOption "TPM-backed FIDO2 authenticator daemon";

    package = lib.mkPackageOption pkgs "tpm-passkey" { };

    tpmPath = mkOption {
      type = types.str;
      default = "/dev/tpmrm0";
      description = "TPM device path";
    };

    uhidPath = mkOption {
      type = types.str;
      default = "/dev/uhid";
      description = "UHID device path";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    services.udev.packages = [ cfg.package ];

    security.polkit.enable = true;

    systemd.services.tpm-passkey = {
      description = "TPM-backed FIDO2 authenticator";
      after = [
        "systemd-logind.service"
        "polkit.service"
      ];
      requires = [ "systemd-logind.service" ];
      wants = [ "polkit.service" ];
      wantedBy = [ "multi-user.target" ];

      unitConfig = {
        ConditionPathExists = [
          cfg.uhidPath
          cfg.tpmPath
        ];
      };

      path = [ cfg.package ];

      script = ''
        exec tpm-passkey daemon --store-dir /var/lib/tpm-passkey --tpm-path "${cfg.tpmPath}" --uhid-path "${cfg.uhidPath}"
      '';

      serviceConfig = {
        NoNewPrivileges = true;
        PrivateDevices = false;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        Restart = "on-failure";
        RestartSec = 2;
        RuntimeDirectory = "tpm-passkey";
        RuntimeDirectoryMode = "0700";
        StateDirectory = "tpm-passkey";
        StateDirectoryMode = "0700";
        Type = "simple";
      };
    };
  };
}
