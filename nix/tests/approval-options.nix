# Pure module evaluation: startup policy must not depend on a live desktop.
{ pkgs, package }:
let
  evaluate =
    settings:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      inherit pkgs;
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        ../nixos-module.nix
        {
          system.stateVersion = "25.11";
          services.tpm-passkey = {
            package = package.daemon;
            cliPackage = package.cli;
            approval.package = package.gtk;
          };
        }
        { services.tpm-passkey = settings; }
      ];
    }).config;
  defaults = evaluate { enable = true; };
  disabled = evaluate { };
  noAgent = evaluate {
    enable = true;
    approval.enable = false;
  };
  xdg = evaluate {
    enable = true;
    approval.startup = "xdg-autostart";
  };
  manual = evaluate {
    enable = true;
    approval.startup = "manual";
  };
  hasUnit = cfg: builtins.hasAttr "tpm-passkey-approval-gtk" cfg.systemd.user.services;
  hasAutostart =
    cfg: builtins.hasAttr "xdg/autostart/tpm-passkey-approval-gtk.desktop" cfg.environment.etc;
in
assert defaults.services.tpm-passkey.approval.enable;
assert defaults.services.tpm-passkey.approval.startup == "systemd";
assert hasUnit defaults && !hasAutostart defaults;
assert
  defaults.systemd.user.services.tpm-passkey-approval-gtk.serviceConfig.ExecStart
  == pkgs.lib.getExe package.gtk;
assert
  !disabled.services.tpm-passkey.approval.enable && !hasUnit disabled && !hasAutostart disabled;
assert !hasUnit noAgent && !hasAutostart noAgent;
assert !(builtins.elem package.gtk noAgent.environment.systemPackages);
assert !hasUnit xdg && hasAutostart xdg;
assert !hasUnit manual && !hasAutostart manual;
assert builtins.elem package.gtk manual.environment.systemPackages;
pkgs.writeText "tpm-passkey-approval-options-checked" "approval defaults and startup overrides evaluated successfully\n"
