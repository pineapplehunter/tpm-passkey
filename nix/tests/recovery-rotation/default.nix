{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "recovery-rotation";
  reason = "Verify multi-key recovery/PCR updates, old-phrase rejection after rotation, and token usage accounting without changing either registered passkey.";
  testScript = ''
    set_recovery_phrase("old-recovery-phrase")
    mgmt("config set default-pcr-policy 1 7")
    for user in ["first", "second"]:
        machine.succeed(f"mkdir -p /tmp/{user}")
        machine.succeed(f"python3 ${../register.py} /tmp/{user} recovery.example.test {user} {user} registration false")

    def assertions(allowed=True):
        for user in ["first", "second"]:
            command = f"python3 ${../assert.py} /tmp/{user} recovery.example.test assertion"
            (machine.succeed if allowed else machine.fail)(command)

    assertions()
    check_token_usage(0)
    extend_pcr("a")
    assertions(False)
    recover("old-recovery-phrase")
    assertions()
    check_token_usage(1)
    set_recovery_phrase("new-recovery-phrase", "old-recovery-phrase")
    check_token_usage(1)

    extend_pcr("b")
    assertions(False)
    rejected = recover("old-recovery-phrase")
    assert sum("error" in line.split() for line in rejected.splitlines()) == 2, rejected
    check_token_usage(1)
    assertions(False)
    recover("new-recovery-phrase")
    assertions()
    check_token_usage(2)

    extend_pcr("c")
    assertions(False)
    recover("new-recovery-phrase", "update-pcr-policy --pcr 7 --all")
    assertions()
    check_token_usage(3)
    rows = mgmt("list-credentials").strip().splitlines()
    assert len(rows) == 2 and all(row.split("\t")[5] == "7" for row in rows), rows
    assert "default_pcr_policy\t1,7" in mgmt("config show")
  '';
}
