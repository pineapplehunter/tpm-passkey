{
  lib,
  rustPlatform,
  pkg-config,
  tpm2-tss,
  gtk4,
  libadwaita,
  wrapGAppsHook4,
  dbus,
  component ? "daemon",
}:
let
  names = {
    daemon = "tpm-passkey-daemon";
    cli = "tpm-passkey";
    gtk = "tpm-passkey-approval-gtk";
  };
  name = names.${component};
in
rustPlatform.buildRustPackage {
  pname = name;
  version = (lib.fromTOML (lib.readFile ../Cargo.toml)).package.version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../.sqlx
      ../Cargo.lock
      ../Cargo.toml
      ../assets
      ../crates
      ../migrations
      ../src
    ];
  };
  _structuredAttrs = true;
  strictDeps = true;
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "-p"
    name
  ];
  cargoTestFlags = [
    "-p"
    name
  ]
  ++ lib.optionals (component == "daemon") [
    "--"
    "--include-ignored"
  ];
  nativeCheckInputs = lib.optionals (component == "daemon") [ dbus ];
  env.SQLX_OFFLINE = "true";
  nativeBuildInputs = [
    pkg-config
  ]
  ++ lib.optionals (component == "daemon") [ rustPlatform.bindgenHook ]
  ++ lib.optionals (component == "gtk") [ wrapGAppsHook4 ];
  buildInputs =
    lib.optionals (component == "daemon") [ tpm2-tss ]
    ++ lib.optionals (component == "gtk") [
      gtk4
      libadwaita
    ];
  postPatch = lib.optionalString (component == "daemon") ''
    substituteInPlace assets/tpm-passkey.service --replace-fail "/usr/bin" "$out/bin"
  '';
  postInstall = lib.optionalString (component == "daemon") ''
    install -D -m 0644 assets/tpm-passkey.rules "$out/lib/udev/rules.d/99-tpm-passkey.rules"
    install -D -m 0644 assets/tpm-passkey.service "$out/lib/systemd/system/tpm-passkey.service"
    install -D -m 0644 assets/tpm-passkey.policy "$out/share/polkit-1/actions/tpm-passkey.policy"
    install -D -m 0644 assets/tpm-passkey-dbus.conf "$out/share/dbus-1/system.d/tpm-passkey.conf"
  '';
  meta.mainProgram = name;
}
