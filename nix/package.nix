{
  lib,
  rustPlatform,
  pkg-config,
  tpm2-tss,
}:
rustPlatform.buildRustPackage {
  pname = (lib.fromTOML (lib.readFile ../Cargo.toml)).package.name;
  version = (lib.fromTOML (lib.readFile ../Cargo.toml)).package.version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../.sqlx
      ../Cargo.lock
      ../Cargo.toml
      ../assets
      ../migrations
      ../src
    ];
  };

  _structuredAttrs = true;
  strictDeps = true;

  cargoLock.lockFile = ../Cargo.lock;

  env.SQLX_OFFLINE = "true";

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];

  buildInputs = [
    tpm2-tss
  ];

  postPatch = ''
    substituteInPlace assets/tpm-passkey.service \
      --replace-fail "/usr/bin" "$out/bin"
  '';

  postInstall = ''
    install -v -D -m 0644 assets/tpm-passkey.rules "$out/lib/udev/rules.d/99-tpm-passkey.rules"
    install -v -D -m 0644 assets/tpm-passkey.service "$out/lib/systemd/system/tpm-passkey.service"
    install -v -D -m 0644 assets/tpm-passkey.policy "$out/share/polkit-1/actions/tpm-passkey.policy"
  '';
}
