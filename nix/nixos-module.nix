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
  agent = lib.getExe cfg.approvalGtk.package;
  autostart = pkgs.writeShellScript "tpm-passkey-approval-autostart" ''
    if ${pkgs.coreutils}/bin/id -nG | ${pkgs.gnugrep}/bin/grep -qw -- ${lib.escapeShellArg cfg.accessGroup}; then
      exec ${agent}
    fi
  '';
in
{
  options.services.tpm-passkey = {
    enable = mkEnableOption "TPM-backed FIDO2 authenticator daemon";
    package = lib.mkPackageOption pkgs "tpm-passkey-daemon" { };
    cliPackage = lib.mkPackageOption pkgs "tpm-passkey" { };
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
    accessGroup = mkOption {
      type = types.str;
      default = "tpm-passkey";
      description = "Group eligible for agent registration and management of the single shared credential store. Membership is never assigned automatically.";
    };
    managementAuthentication = mkOption {
      type = types.enum [
        "admin"
        "self"
      ];
      default = "admin";
      description = "Polkit authentication required for group-member management mutations, without retained authorization. Reads and agent registration are noninteractive.";
    };
    approvalGtk = {
      enable = mkEnableOption "the unprivileged GTK approval agent (never built-in UV)";
      package = lib.mkPackageOption pkgs "tpm-passkey-approval-gtk" { };
      startup = mkOption {
        type = types.enum [
          "xdg-autostart"
          "systemd"
          "manual"
        ];
        default = "xdg-autostart";
        description = "Start with desktop autostart, a correctly integrated graphical-session.target, or manually. No lingering or root display access is enabled.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "[a-z_][a-z0-9_-]*" cfg.accessGroup != null;
        message = "services.tpm-passkey.accessGroup must be a simple Unix group name";
      }
    ];
    users.groups.${cfg.accessGroup} = { };
    # polkit discovers share/polkit-1/actions through the system profile.
    environment.systemPackages = [
      cfg.package
      cfg.cliPackage
    ]
    ++ lib.optional cfg.approvalGtk.enable cfg.approvalGtk.package;
    services.udev.packages = [ cfg.package ];
    services.dbus.packages = [ cfg.package ];
    security.polkit.enable = true;
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        var actions = [
          "io.github.pineapplehunter.tpm-passkey.register-agent",
          "io.github.pineapplehunter.tpm-passkey.read",
          "io.github.pineapplehunter.tpm-passkey.manage-recovery",
          "io.github.pineapplehunter.tpm-passkey.manage-settings"
        ];
        if (actions.indexOf(action.id) < 0) return polkit.Result.NOT_HANDLED;
        // Root already controls the daemon/store. The group gates ordinary users.
        if (subject.user == "root") return polkit.Result.YES;
        if (!subject.isInGroup(${builtins.toJSON cfg.accessGroup})) return polkit.Result.NO;
        if (action.id == actions[0] || action.id == actions[1]) return polkit.Result.YES;
        return polkit.Result.${
          if cfg.managementAuthentication == "self" then "AUTH_SELF" else "AUTH_ADMIN"
        };
      });
    '';
    systemd.services.tpm-passkey = {
      description = "TPM-backed FIDO2 authenticator";
      after = [
        "dbus.service"
        "systemd-logind.service"
        "polkit.service"
      ];
      requires = [
        "dbus.service"
        "systemd-logind.service"
      ];
      wants = [ "polkit.service" ];
      wantedBy = [ "multi-user.target" ];
      unitConfig.ConditionPathExists = [
        cfg.uhidPath
        cfg.tpmPath
      ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --store-dir /var/lib/tpm-passkey --tpm-path ${cfg.tpmPath} --uhid-path ${cfg.uhidPath}";
        Type = "dbus";
        BusName = "io.github.pineapplehunter.TpmPasskey1";
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
      };
    };
    systemd.user.services.tpm-passkey-approval-gtk =
      mkIf (cfg.approvalGtk.enable && cfg.approvalGtk.startup == "systemd")
        {
          description = "GTK passkey user-presence approval agent";
          wantedBy = [ "graphical-session.target" ];
          after = [ "graphical-session.target" ];
          partOf = [ "graphical-session.target" ];
          unitConfig.ConditionGroup = cfg.accessGroup;
          serviceConfig = {
            ExecStart = agent;
            Restart = "on-failure";
            RestartSec = 2;
          };
        };
    environment.etc."xdg/autostart/tpm-passkey-approval-gtk.desktop" =
      mkIf (cfg.approvalGtk.enable && cfg.approvalGtk.startup == "xdg-autostart")
        {
          text = ''
            [Desktop Entry]
            Type=Application
            Name=TPM Passkey Approval
            Comment=Confirm TPM-backed passkey operations
            Exec=${autostart}
            TryExec=${agent}
            Terminal=false
            NoDisplay=true
          '';
        };
  };
}
