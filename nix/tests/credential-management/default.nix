{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "credential-management";
  reason = "Check Protocol 1-authenticated credential management, successful RP/credential continuations, user updates and interruption of a still-valid enumeration.";
  testScript = ''
    setup_migration()
    expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    for user, rp in [("first", "manage.example.test"), ("second", "manage.example.test"), ("third", "other.example.test")]:
        machine.succeed(f"mkdir -p /tmp/{user}")
        machine.succeed(f"python3 ${../register.py} /tmp/{user} {rp} {user} {user} registration true 1234")
    machine.succeed("python3 ${./scenario.py}", timeout=45)
  '';
}
