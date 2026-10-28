{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "recovery-reboot";
  reason = "Persist a PCR-bound key across VM reboot, recover changed PCRs with the supplied phrase, and require a fresh explicit enrollment unlock.";
  testScript = ''
    set_recovery_phrase("reboot-recovery-phrase")
    mgmt("config set default-pcr-policy 1 7")
    extend_pcr("a")  # This enrolled state cannot survive a PCR reset on reboot.
    machine.succeed("mkdir -p /tmp/credential /tmp/enrollment")
    machine.succeed("python3 ${../register.py} /tmp/credential reboot.example.test alice user-1 registration false")
    assertion = "python3 ${../assert.py} /tmp/credential reboot.example.test assertion"
    enrollment = "python3 ${../register.py} /tmp/enrollment enrollment.example.test alice user-2 registration false"
    machine.succeed(assertion)
    check_token_usage(0)

    machine.shutdown()
    machine.wait_for_unit("getty@tty1.service", timeout=60)
    login_alice()
    start_daemon()
    machine.fail(assertion)
    machine.fail(enrollment)
    recover("reboot-recovery-phrase")
    machine.succeed(assertion)
    check_token_usage(1)
    machine.fail(enrollment)  # Recovery approval must not unlock enrollment.
    mgmt_expect("config unlock-recovery",
        'expect "Enter recovery passphrase: "; send "reboot-recovery-phrase\\r"; expect eof')
    machine.succeed(enrollment)
    assert len(mgmt("list-credentials").strip().splitlines()) == 2
  '';
}
