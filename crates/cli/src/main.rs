use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{WrapErr, bail, eyre},
};
use rpassword::prompt_password;
use tpm_passkey_protocol as management;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Manage the Linux TPM-backed FIDO2/WebAuthn authenticator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List credentials from the running daemon
    ListCredentials,
    /// Change the recovery passphrase for all credentials via the daemon
    UpdatePassphrase,
    /// Re-sign PCR policy for all credentials using current PCR values
    UpdatePcrReference,
    /// Update PCR policy with a new PCR selection
    UpdatePcrPolicy(PcrPolicyArgs),
    /// Show or change persistent daemon configuration
    Config(ConfigArgs),
}

#[derive(Debug, clap::Args)]
struct PcrPolicyArgs {
    /// PCR indices to bind (repeatable, e.g. --pcr 1 --pcr 7)
    #[arg(long, short)]
    pcr: Vec<u32>,

    /// Apply to all credentials instead of listing specific IDs
    #[arg(long)]
    all: bool,

    /// Credential IDs (hex) to update
    credential_ids: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Show effective persistent configuration
    Show,
    /// Unlock recovery-enabled registration until the daemon restarts
    UnlockRecovery,
    /// Set a persistent configuration value
    Set(ConfigSetArgs),
}

#[derive(Debug, clap::Args)]
struct ConfigSetArgs {
    #[command(subcommand)]
    setting: ConfigSetCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigSetCommand {
    /// Set the default PCR policy for newly created credentials
    DefaultPcrPolicy(DefaultPcrPolicyArgs),
    /// Set or rotate the recovery passphrase and credential recovery slots
    RecoveryPassphrase,
}

#[derive(Debug, clap::Args)]
struct DefaultPcrPolicyArgs {
    /// PCR indices for future credentials (e.g. 1 7); requires recovery
    #[arg(required_unless_present = "disable", num_args = 1..)]
    pcr_indices: Vec<u32>,

    /// Disable PCR binding for future registrations; existing keys are unchanged
    #[arg(long, conflicts_with = "pcr_indices")]
    disable: bool,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Command::ListCredentials => run_list_credentials(),
        Command::UpdatePassphrase => run_update_passphrase(),
        Command::UpdatePcrReference => run_update_pcr_reference(),
        Command::UpdatePcrPolicy(args) => run_update_pcr_policy(args),
        Command::Config(args) => run_config(args),
    }
}

fn run_list_credentials() -> Result<()> {
    let request = management::ManagementRequest::ListCredentials;
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    if let Some(result) = &response.result
        && let Some(credentials) =
            management::value_get(result, "credentials").and_then(|v| v.as_array())
    {
        for cred in credentials {
            let id_hex = management::value_get(cred, "id")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            let id = base64_credential_id(id_hex)?;
            let rp_id = management::value_get(cred, "rp_id")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            let user_name = management::value_get(cred, "user_name")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            let registered_at = management::value_get(cred, "registered_at")
                .and_then(|v| v.as_text())
                .unwrap_or("unknown");
            let last_used_at = management::value_get(cred, "last_used_at")
                .and_then(|v| v.as_text())
                .unwrap_or("never");
            let pcr_indices = management::value_get(cred, "pcr_indices")
                .map(format_pcr_selection)
                .unwrap_or_else(|| "none".to_owned());
            println!(
                "{id}\t{}\t{}\t{}\t{}\t{pcr_indices}",
                terminal_field(rp_id),
                terminal_field(user_name),
                terminal_field(registered_at),
                terminal_field(last_used_at)
            );
        }
    }
    Ok(())
}

// Website-controlled names must not become terminal commands or forged TSV rows.
fn terminal_field(text: &str) -> String {
    use std::fmt::Write;
    let mut escaped = String::new();
    for ch in text.chars() {
        if ch.is_control()
            || (ch.is_whitespace() && ch != ' ')
            || unicode_general_category::get_general_category(ch)
                == unicode_general_category::GeneralCategory::Format
        {
            let _ = write!(escaped, "\\u{{{:x}}}", ch as u32);
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn base64_credential_id(id_hex: &str) -> Result<String> {
    Ok(STANDARD
        .encode(hex::decode(id_hex).wrap_err("decoding credential ID from daemon response")?))
}

fn run_update_passphrase() -> Result<()> {
    let old = read_secret("Enter current daemon passphrase (leave empty if not set yet): ")?;
    let new = prompt_password_confirm("Enter new daemon passphrase: ")?;
    let request = management::ManagementRequest::UpdatePassphrase {
        old_passphrase: if old.is_empty() { None } else { Some(old) },
        new_passphrase: new,
    };
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    println!("Daemon passphrase updated.");
    Ok(())
}

fn run_unlock_recovery() -> Result<()> {
    let passphrase = read_secret("Enter recovery passphrase: ")?;
    let response =
        management::send_request(&management::ManagementRequest::UnlockRecovery { passphrase })?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    println!("Recovery enrollment unlocked until daemon restart.");
    Ok(())
}

fn run_update_pcr_reference() -> Result<()> {
    let passphrase = read_nonempty_secret("Enter recovery passphrase: ")?;
    let request = management::ManagementRequest::UpdatePcrReference { passphrase };
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    if let Some(result) = &response.result
        && let Some(results) = management::value_get(result, "results").and_then(|v| v.as_array())
    {
        for r in results {
            let id = management::value_get(r, "credential")
                .and_then(|v| v.as_text())
                .unwrap_or("?");
            let status = management::value_get(r, "status")
                .and_then(|v| v.as_text())
                .unwrap_or("?");
            println!("{id}\t{status}");
        }
    }
    Ok(())
}

fn run_update_pcr_policy(args: PcrPolicyArgs) -> Result<()> {
    validate_pcr_indices(&args.pcr).wrap_err("invalid PCR selection")?;
    if args.all && !args.credential_ids.is_empty() {
        bail!("--all cannot be combined with credential IDs");
    }
    if !args.all && args.credential_ids.is_empty() {
        bail!("provide --all or at least one credential ID");
    }
    let passphrase = read_nonempty_secret("Enter recovery passphrase: ")?;

    let credential_target = if args.all {
        management::CredentialTarget::All { all: true }
    } else {
        management::CredentialTarget::Ids {
            credential_ids: args.credential_ids,
        }
    };

    let request = management::ManagementRequest::UpdatePcrPolicy {
        passphrase,
        pcr_indices: args.pcr,
        credential_target,
    };
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    if let Some(result) = &response.result
        && let Some(results) = management::value_get(result, "results").and_then(|v| v.as_array())
    {
        for r in results {
            let id = management::value_get(r, "credential")
                .and_then(|v| v.as_text())
                .unwrap_or("?");
            let status = management::value_get(r, "status")
                .and_then(|v| v.as_text())
                .unwrap_or("?");
            println!("{id}\t{status}");
        }
    }
    Ok(())
}

fn run_config(args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Show => run_config_show(),
        ConfigCommand::UnlockRecovery => run_unlock_recovery(),
        ConfigCommand::Set(args) => match args.setting {
            ConfigSetCommand::DefaultPcrPolicy(args) => run_set_default_pcr_policy(args),
            ConfigSetCommand::RecoveryPassphrase => run_update_passphrase(),
        },
    }
}

fn run_config_show() -> Result<()> {
    let response = management::send_request(&management::ManagementRequest::ShowConfig)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    let result = response
        .result
        .as_ref()
        .ok_or_else(|| eyre!("daemon returned no configuration"))?;
    let default_pcr_policy = management::value_get(result, "default_pcr_policy")
        .map(format_pcr_selection)
        .unwrap_or_else(|| "none".to_owned());
    let recovery_passphrase_configured =
        management::value_get(result, "recovery_passphrase_configured")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
    println!("default_pcr_policy\t{default_pcr_policy}");
    println!("recovery_passphrase_configured\t{recovery_passphrase_configured}");
    Ok(())
}

fn run_set_default_pcr_policy(args: DefaultPcrPolicyArgs) -> Result<()> {
    let request = if args.disable {
        management::ManagementRequest::DisableDefaultPcrPolicy
    } else {
        validate_pcr_indices(&args.pcr_indices).wrap_err("invalid PCR selection")?;
        management::ManagementRequest::SetDefaultPcrPolicy {
            pcr_indices: args.pcr_indices.clone(),
        }
    };
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    if args.disable {
        println!(
            "PCR binding disabled for future registrations; existing credentials are unchanged."
        );
    } else {
        println!(
            "default PCR policy set to {:?} for future registrations",
            args.pcr_indices
        );
    }
    Ok(())
}

fn format_pcr_selection(value: &ciborium::value::Value) -> String {
    if value.as_array().is_some_and(|values| !values.is_empty()) {
        format_integer_array(value)
    } else {
        "none".to_owned()
    }
}

fn format_integer_array(value: &ciborium::value::Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_integer())
        .filter_map(|value| u64::try_from(value).ok())
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// Keep every input protected even on an error or a discarded confirmation.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        prompt_password(prompt).wrap_err("reading passphrase")?,
    ))
}

fn read_nonempty_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let password = read_secret(prompt)?;
    if password.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(password)
}

fn validate_password_pair(password: &str, confirmation: &str) -> Result<()> {
    if password.is_empty() {
        bail!("passphrase must not be empty");
    }
    if password != confirmation {
        bail!("passphrases do not match");
    }
    Ok(())
}

fn prompt_password_confirm(prompt: &str) -> Result<Zeroizing<String>> {
    let password = read_secret(prompt)?;
    let confirmation = read_secret("Confirm passphrase: ")?;
    validate_password_pair(&password, &confirmation)?;
    Ok(password)
}

// Only numeric sanity checking belongs in the client. The daemon validates
// supported TPM banks, duplicates, recovery constraints and actual policy.
fn validate_pcr_indices(indices: &[u32]) -> Result<()> {
    if indices.is_empty() || indices.iter().any(|&index| index > 23) {
        bail!("PCR indices must be in 0..=23 and selection must not be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_command_uses_show_and_nested_set_hierarchy() {
        let show =
            Cli::try_parse_from(["tpm-passkey", "config", "show"]).expect("parse config show");
        assert!(matches!(
            show.command,
            Command::Config(ConfigArgs {
                command: ConfigCommand::Show
            })
        ));

        let set = Cli::try_parse_from([
            "tpm-passkey",
            "config",
            "set",
            "default-pcr-policy",
            "1",
            "7",
        ])
        .expect("parse nested default PCR policy");
        let Command::Config(ConfigArgs {
            command:
                ConfigCommand::Set(ConfigSetArgs {
                    setting: ConfigSetCommand::DefaultPcrPolicy(args),
                }),
        }) = set.command
        else {
            panic!("unexpected config command");
        };
        assert_eq!(args.pcr_indices, vec![1, 7]);

        let recovery = Cli::try_parse_from(["tpm-passkey", "config", "set", "recovery-passphrase"])
            .expect("parse recovery passphrase setting");
        assert!(matches!(
            recovery.command,
            Command::Config(ConfigArgs {
                command: ConfigCommand::Set(ConfigSetArgs {
                    setting: ConfigSetCommand::RecoveryPassphrase
                })
            })
        ));

        assert!(Cli::try_parse_from(["tpm-passkey", "set-default-pcr-policy", "7"]).is_err());
    }

    #[test]
    fn pcr_disable_is_explicit_and_config_output_distinguishes_no_binding() {
        let cli = Cli::try_parse_from([
            "tpm-passkey",
            "config",
            "set",
            "default-pcr-policy",
            "--disable",
        ])
        .unwrap();
        let Command::Config(ConfigArgs {
            command:
                ConfigCommand::Set(ConfigSetArgs {
                    setting: ConfigSetCommand::DefaultPcrPolicy(args),
                }),
        }) = cli.command
        else {
            panic!("PCR configuration command")
        };
        assert!(args.disable);
        assert!(args.pcr_indices.is_empty());
        assert!(
            Cli::try_parse_from(["tpm-passkey", "config", "set", "default-pcr-policy",]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tpm-passkey",
                "config",
                "set",
                "default-pcr-policy",
                "--disable",
                "7",
            ])
            .is_err()
        );
        assert_eq!(format_pcr_selection(&ciborium::value::Value::Null), "none");
        assert_eq!(
            format_pcr_selection(&ciborium::value::Value::Array(vec![])),
            "none"
        );
        assert_eq!(
            format_pcr_selection(&ciborium::value::Value::Array(vec![1.into(), 7.into()])),
            "1,7"
        );
    }

    #[test]
    fn credential_ids_are_printed_as_standard_base64() {
        assert_eq!(base64_credential_id("0001feff").unwrap(), "AAH+/w==");
    }

    #[test]
    fn daemon_and_approval_are_not_cli_commands() {
        assert!(Cli::try_parse_from(["tpm-passkey", "daemon"]).is_err());
        assert!(Cli::try_parse_from(["tpm-passkey", "approve"]).is_err());
    }

    #[test]
    fn website_fields_cannot_control_terminals_or_forge_rows() {
        let escaped = terminal_field("site\u{1b}]52;c;AAAA\u{7}\tname\n\u{202e}\u{200b}");
        assert!(!escaped.chars().any(char::is_control));
        assert!(escaped.contains("\\u{1b}") && escaped.contains("\\u{9}"));
        assert!(escaped.contains("\\u{202e}") && escaped.contains("\\u{200b}"));
        assert_eq!(terminal_field("ordinary site"), "ordinary site");
    }

    #[test]
    fn password_confirmation_rejects_empty_and_mismatched_inputs() {
        assert!(validate_password_pair("", "").is_err());
        assert!(validate_password_pair("first", "second").is_err());
        assert!(validate_password_pair("same", "same").is_ok());
    }

    #[test]
    fn pcr_sanity_checks_bounds_and_empty_selection() {
        assert!(validate_pcr_indices(&[]).is_err());
        assert!(validate_pcr_indices(&[24]).is_err());
        assert!(validate_pcr_indices(&[0, 7, 23]).is_ok());
    }
}
