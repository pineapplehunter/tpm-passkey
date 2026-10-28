{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "factory-reset";
  reason = "Reset must invalidate a resident passkey, clear the old client PIN and allow fresh PIN setup, independently of PIN-management workflows.";
  testScript = ''
    expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential reset.example.test alice user-1 registration true 1234")
    machine.succeed("python3 ${../assert.py} /tmp/credential reset.example.test before-reset")
    machine.succeed("systemctl restart tpm-passkey")
    expect_command("fido2-manage -reset -device 1",
        'expect "Are you sure you want to proceed?"; send "Y\\r"; expect eof')
    assert mgmt("list-credentials").strip() == ""
    machine.fail("python3 ${../assert.py} /tmp/credential reset.example.test after-reset")
    expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "5678\\r"; '
        'expect "Enter the same PIN again"; send "5678\\r"; expect eof')
  '';
}
