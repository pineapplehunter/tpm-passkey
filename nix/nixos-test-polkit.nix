{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    {
      checks.nixos-polkit = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2-polkit";

        nodes.machine = {
          imports = [ ./nixos-module.nix ];

          virtualisation.tpm.enable = true;

          users.users.alice = {
            isNormalUser = true;
            password = "alice";
          };

          services.linux-tpm-fido2 = {
            enable = true;
            package = config.packages.default;
            tpmPath = "/dev/tpm0";
            uhidPath = "/dev/uhid";
          };

          systemd.services.linux-tpm-fido2.wantedBy = lib.mkForce [ ];
          systemd.services.linux-tpm-fido2.environment.RUST_LOG = "linux_tpm_fido2=debug,sqlx=warn,zbus=warn";

          security.polkit.extraConfig = ''
            polkit.addRule(function(action, subject) {
              if (action.id == "io.github.pineapplehunter.linux-tpm-fido2.approve"
                  && subject.user == "alice") {
                return polkit.Result.YES;
              }
            });
          '';

          environment.systemPackages = with pkgs; [
            fido2-manage
            expect
            tpm2-tools
            (python3.withPackages (ps: [
              ps.cbor2
              ps.fido2
            ]))
          ];
        };

        testScript = ''
          import shlex

          def check_token_usage(expected):
              script = (
                  'import sqlite3; '
                  'db = sqlite3.connect("/var/lib/linux-tpm-fido2/credentials.sqlite"); '
                  'rows = db.execute("SELECT used_count, last_used FROM credential_tokens").fetchall(); '
                  f'assert rows and all(count == {expected} and ((used is None) == ({expected} == 0)) '
                  'for count, used in rows), rows'
              )
              machine.succeed(f"python3 -c {shlex.quote(script)}")

          def login_alice():
              machine.send_key("ctrl-alt-f1")
              machine.wait_until_tty_matches("1", "login:")
              machine.send_chars("alice\n")
              machine.wait_until_tty_matches("1", "Password:")
              machine.send_chars("alice\n")
              machine.wait_until_tty_matches("1", "alice@")

          def mgmt(cmd):
              """Run a no-password management subcommand."""
              return machine.succeed(f"linux-tpm-fido2 {cmd}")

          def mgmt_expect(cmd, expect_script):
              """Run a management subcommand with an expect script for passphrase input."""
              full = (
                  f"expect -c '"
                  f"spawn linux-tpm-fido2 {cmd}; "
                  + expect_script
                  + "'"
              )
              return machine.succeed(full)

          machine.wait_for_unit("getty@tty1.service")
          login_alice()
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")

          # -- fido2-manage subcommands (no PIN needed) --
          output = machine.succeed("fido2-manage -list")
          print("fido2-manage -list output:")
          print(output)
          assert "FIDO2" in output or "1209" in output or "linux-tpm" in output.lower(), (
              f"Expected device listing, got: {output}"
          )

          output = machine.succeed("fido2-manage -info -device 1")
          print("fido2-manage -info output:")
          print(output)
          assert "FIDO_2_1" in output, f"Expected FIDO2 version info, got: {output}"
          assert "rk" in output, f"Expected resident key support info, got: {output}"

          # -- list-credentials (no credentials yet) --
          output = mgmt("list-credentials")
          print("list-credentials (empty):", output)
          assert output.strip() == "", f"Expected empty listing, got: {output}"

          # -- config show/set --
          output = mgmt("config show")
          print("config show (defaults):", output)
          assert "default_pcr_policy\t7" in output, f"Unexpected output: {output}"
          assert "recovery_passphrase_configured\tfalse" in output, f"Unexpected output: {output}"

          output = mgmt("config set default-pcr-policy 1 7")
          print("config set default-pcr-policy:", output)
          assert "default PCR policy set to [1, 7]" in output, f"Unexpected output: {output}"

          output = mgmt("config show")
          assert "default_pcr_policy\t1,7" in output, f"Unexpected output: {output}"

          # -- Set daemon passphrase (first-time: empty old passphrase) --
          mgmt_expect(
              "update-passphrase",
              'expect "Enter current daemon passphrase (leave empty if not set yet): "; '
              'send "\\r"; '
              'expect "Enter new daemon passphrase: "; '
              'send "test-recovery-passphrase\\r"; '
              'expect eof',
          )

          # -- register and assert via polkit authorization --
          machine.succeed("mkdir -p /tmp/linux-tpm-fido2-smoke")
          ret_reg, output_reg = machine.execute(
              "python3 ${./tests/smoke_register.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test alice user-123 'make credential challenge' false"
          )
          print("### registration stdout/stderr:")
          print("### " + output_reg.strip().replace("\n", "\n### "))
          if ret_reg != 0:
              journal = machine.succeed("journalctl -u linux-tpm-fido2 --no-pager -n 50")
              print("### daemon journal after registration failure:")
              for line in journal.strip().split("\n"):
                  print("### " + line)
              raise Exception(f"Registration failed:\n{output_reg}")

          ret, output = machine.execute(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )
          print("### assertion stdout/stderr:")
          print("### " + output.strip().replace("\n", "\n### "))
          if ret != 0:
              journal = machine.succeed("journalctl -u linux-tpm-fido2 --no-pager -n 50")
              print("### daemon journal after assertion failure:")
              for line in journal.strip().split("\n"):
                  print("### " + line)
              raise Exception(f"Assertion failed:\n{output}")

          # -- regression test for tpm session exhaustion --
          for _ in range(20):
            machine.succeed(
                "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
                + "login.example.test 'assert credential challenge'"
            )

          # -- CTAPHID and CTAP 2.1 compliance checks --
          ret, output = machine.execute(
              "python3 ${./tests/ctap_compliance.py} compliance.example.test"
          )
          print("### CTAP compliance stdout/stderr:")
          print("### " + output.strip().replace("\n", "\n### "))
          if ret != 0:
              journal = machine.succeed("journalctl -u linux-tpm-fido2 --no-pager -n 100")
              print("### daemon journal after CTAP compliance failure:")
              for line in journal.strip().split("\n"):
                  print("### " + line)
              raise Exception(f"CTAP compliance checks failed:\n{output}")

          # -- list-credentials (after registration) --
          output = mgmt("list-credentials")
          print("list-credentials (after registration):", output)
          assert "login.example.test" in output, f"Expected credential listing, got: {output}"
          assert output.count("compliance.example.test") == 2, (
              f"Expected two discoverable compliance credentials, got: {output}"
          )
          rows = [line.split("\t") for line in output.strip().splitlines()]
          assert all(len(row) == 6 for row in rows), f"Expected six listing columns: {output}"
          assert all(row[3] != "unknown" for row in rows), f"Missing registration date: {output}"
          assert all(row[4] != "never" for row in rows), f"Missing last-used date: {output}"
          assert all(row[5] == "1,7" for row in rows), f"Missing bound PCR indices: {output}"

          check_token_usage(0)  # Ordinary assertions do not use recovery tokens.

          # -- PCR update via update-pcr-reference (expect for passphrase) --
          machine.succeed("tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
          machine.fail(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )
          mgmt_expect(
              "update-pcr-reference",
              'expect "Enter recovery passphrase: "; '
              'send "test-recovery-passphrase\\r"; '
              'expect eof',
          )
          machine.succeed(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )

          check_token_usage(1)

          # -- Passphrase change via update-passphrase (expect for old+new) --
          mgmt_expect(
              "update-passphrase",
              'expect "Enter current daemon passphrase (leave empty if not set yet): "; '
              'send "test-recovery-passphrase\\r"; '
              'expect "Enter new daemon passphrase: "; '
              'send "new-recovery-passphrase\\r"; '
              'expect eof',
          )

          check_token_usage(1)  # Rewrapping does not count as token use.

          # -- Old passphrase rejected even while enrollment is unlocked --
          machine.succeed("tpm2_pcrextend 7:sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
          machine.fail(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )
          rejected = mgmt_expect(
              "update-pcr-reference",
              'expect "Enter recovery passphrase: "; '
              'send "test-recovery-passphrase\\r"; '
              'expect eof',
          )
          assert any("error" in line.split() for line in rejected.splitlines()), rejected
          check_token_usage(1)
          machine.fail(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )
          mgmt_expect(
              "update-pcr-reference",
              'expect "Enter recovery passphrase: "; '
              'send "new-recovery-passphrase\\r"; '
              'expect eof',
          )
          machine.succeed(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )

          check_token_usage(2)

          # -- update-pcr-policy with --all (expect for passphrase) --
          machine.succeed("tpm2_pcrextend 7:sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
          machine.fail(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )
          mgmt_expect(
              "update-pcr-policy --pcr 7 --all",
              'expect "Enter recovery passphrase: "; '
              'send "new-recovery-passphrase\\r"; '
              'expect eof',
          )
          machine.succeed(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )

          check_token_usage(3)

          # -- regression check for reboot persistence --
          machine.shutdown()
          machine.wait_for_unit("getty@tty1.service")
          login_alice()
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          # Re-sign PCR policy after reboot since the TPM state (and therefore
          # PCR values) may differ from the pre-reboot boot environment.
          mgmt_expect(
              "update-pcr-reference",
              'expect "Enter recovery passphrase: "; '
              'send "new-recovery-passphrase\r"; '
              'expect eof',
          )
          machine.succeed(
              "python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke "
              + "login.example.test 'assert credential challenge'"
          )

          check_token_usage(4)

          # Ordinary assertions work while recovery enrollment is locked. New
          # recovery-enabled credentials require an explicit password unlock.
          machine.succeed("mkdir -p /tmp/locked-enrollment")
          register_after_restart = (
              "python3 ${./tests/smoke_register.py} /tmp/locked-enrollment "
              + "enrollment.example.test alice user-enrollment 'enrollment challenge' false"
          )
          machine.fail(register_after_restart)
          mgmt_expect(
              "config unlock-recovery",
              'expect "Enter recovery passphrase: "; '
              'send "new-recovery-passphrase\\r"; '
              'expect eof',
          )
          machine.succeed(register_after_restart)

          # -- list-credentials after reboot --
          output = mgmt("list-credentials")
          print("list-credentials (after reboot):", output)
          assert "login.example.test" in output, f"Expected credential listing, got: {output}"
          assert output.count("compliance.example.test") == 2, (
              f"Expected compliance credentials to survive reboot, got: {output}"
          )

          # -- fido2-manage PIN-dependent subcommands (daemon has no PIN at this point) --
          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -setPIN -device 1; '
              'expect "Enter new PIN"; '
              'send "1234\\r"; '
              'expect "Enter the same PIN again"; '
              'send "1234\\r"; '
              'expect eof'
              "'"
          )

          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -storage -device 1; '
              'expect "Enter PIN"; '
              'send "1234\\r"; '
              'expect eof'
              "'"
          )

          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -changePIN -device 1; '
              'expect "Enter current PIN"; '
              'send "1234\\r"; '
              'expect "Enter new PIN"; '
              'send "5678\\r"; '
              'expect "Enter the same PIN again"; '
              'send "5678\\r"; '
              'expect eof'
              "'"
          )

          # -- credential-management deletion removes storage and assertion access --
          before_delete = mgmt("list-credentials")
          delete_row = next(
              row.split("\t")
              for row in before_delete.strip().splitlines()
              if "compliance.example.test" in row
          )
          machine.succeed(
              "expect -c '"
              + f"spawn fido2-manage -delete -device 1 -credential {delete_row[0]}; "
              + 'expect "Are you sure you want to proceed?"; '
              + 'send "Y\\r"; '
              + 'expect "Enter PIN"; '
              + 'send "5678\\r"; '
              + 'expect eof'
              + "'"
          )
          after_delete = mgmt("list-credentials")
          assert after_delete.count("compliance.example.test") == 1, (
              f"Expected one compliance credential after deletion, got: {after_delete}"
          )

          # -- reset is accepted only just after a new authenticator generation --
          machine.succeed("systemctl restart linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          reset_output = machine.succeed(
              "expect -c '"
              'spawn fido2-manage -reset -device 1; '
              'expect "Are you sure you want to proceed?"; '
              'send "Y\\r"; '
              'expect eof'
              "'"
          )
          assert "Factory reset completed" in reset_output, reset_output
          assert mgmt("list-credentials").strip() == "", (
              "factory reset did not remove all credentials"
          )
        '';
      };
    };
}
