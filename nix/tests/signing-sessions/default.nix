{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "signing-sessions";
  reason = "Repeated PCR-bound assertions must flush transient TPM objects and policy sessions instead of exhausting the TPM's small handle/session limits.";
  testScript = ''
    set_recovery_phrase("signing-session-phrase")
    mgmt("config set default-pcr-policy 7")
    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential sessions.example.test alice user-1 registration false")
    for _ in range(20):
        machine.succeed("python3 ${../assert.py} /tmp/credential sessions.example.test assertion")
    check_token_usage(0)
  '';
}
