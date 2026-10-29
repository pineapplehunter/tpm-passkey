{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    let
      package = {
        daemon = config.packages.daemon;
        cli = config.packages.cli;
        gtk = config.packages.approval-gtk;
      };
    in
    {
      checks =
        lib.listToAttrs (
          map
            (name: {
              name = "nixos-${name}";
              value = pkgs.callPackage (./. + "/${name}/default.nix") {
                inherit pkgs package;
              };
            })
            [
              "management"
              "management-access"
              "ctap-transport"
              "ctap-credentials"
              "credential-management"
              "pin-management"
              "factory-reset"
              "state-integrity"
              "approval-cancel"
              "approval-lifecycle"
              "gtk-approval"
              "signing-sessions"
              "migration-rebind"
              "migration-reboot"
              "migration-upgrade"
            ]
        )
        // {
          approval-options = import ./approval-options.nix { inherit pkgs package; };
        };
    };
}
