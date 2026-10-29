{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "migration-reboot";
  allowReboot = true;
  reason = "Persist migration authorization across a VM reboot, then migrate a key from pre-reboot PCR state to the new measured state.";
  testScript = ''
    setup_migration("reboot migration phrase", [7])
    machine.succeed("tpm2_pcrextend 7:sha256=" + "a" * 64)
    machine.succeed("mkdir -p /var/lib/tpm-passkey/test-fixture/credential")
    machine.succeed("python3 ${../register.py} /var/lib/tpm-passkey/test-fixture/credential reboot.example.test alice user-1 registration false")
    assertion = "python3 ${../assert.py} /var/lib/tpm-passkey/test-fixture/credential reboot.example.test reboot-check"
    machine.succeed(assertion)

    # Let the driver finish receiving this command's framed reply before the
    # guest shuts down its backdoor shell.
    machine.succeed("systemd-run --on-active=1s --unit=migration-test-reboot systemctl reboot")
    machine.wait_for_console_text("reboot: Restarting system", timeout=30)
    machine.connected = False
    machine.wait_for_unit("getty@tty1.service", timeout=60)
    login_alice()
    start_daemon()
    machine.fail(assertion)
    mgmt_expect(
        "migrate --yes",
        'expect "Migration passphrase: "; send "reboot migration phrase\\r"; expect eof',
    )
    machine.succeed(assertion)
  '';
}
