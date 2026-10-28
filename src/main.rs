use std::{
    env, path::PathBuf, sync::Arc, sync::atomic::AtomicBool, sync::mpsc, thread, time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{WrapErr, bail, eyre},
};
use rpassword::prompt_password;
use tpm_passkey::{ctaphid, hid, management, store, tpm};
use uhid_virt::{OutputEvent, StreamError, UHIDDevice};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Linux TPM-backed FIDO2/WebAuthn authenticator daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the UHID FIDO2 daemon with management socket
    Daemon(DaemonArgs),
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
struct DaemonArgs {
    /// Path to the Linux UHID character device
    #[arg(long, default_value = "/dev/uhid")]
    uhid_path: PathBuf,

    /// Path to the TPM resource-manager device
    #[arg(long, default_value = "/dev/tpmrm0")]
    tpm_path: PathBuf,

    /// Directory for development TPM-backed credentials
    #[arg(long, default_value = store::DEV_STORE_DIR)]
    store_dir: PathBuf,

    /// Do not open UHID or TPM devices; only print resolved configuration
    #[arg(long)]
    dry_run: bool,
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
        Command::Daemon(args) => run_daemon(args),
        Command::ListCredentials => run_list_credentials(),
        Command::UpdatePassphrase => run_update_passphrase(),
        Command::UpdatePcrReference => run_update_pcr_reference(),
        Command::UpdatePcrPolicy(args) => run_update_pcr_policy(args),
        Command::Config(args) => run_config(args),
    }
}

fn absolute_path(path: &PathBuf) -> PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn run_daemon(args: DaemonArgs) -> Result<()> {
    let store_dir = absolute_path(&args.store_dir);

    log::info!("tpm-passkey starting");
    log::info!("uhid path: {}", args.uhid_path.display());
    log::info!("tpm path: {}", args.tpm_path.display());
    log::info!("dev store: {}", store_dir.display());
    log::info!(
        "credential database: {}",
        store::credentials_database_path_in_dir(&store_dir).display()
    );

    if args.dry_run {
        log::info!("dry run: not opening UHID or TPM devices");
        return Ok(());
    }

    if let Err(error) = tpm::check_device(&args.tpm_path) {
        log::warn!(
            "warning: TPM device {} is not accessible yet: {error}",
            args.tpm_path.display()
        );
    } else {
        log::info!("TPM device is accessible");
    }

    // Start management socket server in a background thread.
    // The TPM command channel allows the management thread to ask the main
    // daemon thread to perform TPM operations (e.g. update-pcr-reference)
    // since the TPM device cannot be opened by two threads simultaneously.
    let mgmt_stop = Arc::new(AtomicBool::new(false));
    let mgmt_store_dir = store_dir.clone();
    let (tpm_cmd_tx, tpm_cmd_rx) = mpsc::channel::<(
        tpm_passkey::ctap2::TpmCommand,
        mpsc::Sender<tpm_passkey::ctap2::TpmCmdResult>,
    )>();
    let _mgmt_handle = {
        let stop = mgmt_stop.clone();
        let tpm_cmd_tx = tpm_cmd_tx.clone();
        thread::spawn(move || {
            if let Err(e) = management::serve(mgmt_store_dir, Some(tpm_cmd_tx), stop) {
                log::error!("management server failed: {e}");
            }
        })
    };

    let mut device = UHIDDevice::create_with_path(hid::create_params(), &args.uhid_path)
        .wrap_err_with(|| format!("opening UHID device {}", args.uhid_path.display()))?;
    log::info!("created virtual FIDO HID device; waiting for host reports");
    let mut ctaphid = ctaphid::PacketHandler::new(store_dir, Some(args.tpm_path.clone()));

    loop {
        // Process any pending TPM commands from the management thread.
        if let Ok((command, resp_tx)) = tpm_cmd_rx.try_recv() {
            log::debug!("queuing TPM command from management thread");
            ctaphid.queue_tpm_command(command, resp_tx);
        }

        if let Some(ctaphid::PacketOutcome::Response(response)) = ctaphid.poll() {
            log::debug!(
                "uhid tx cid={:#010x} command={} payload_len={}",
                response.cid,
                ctaphid::command_name(response.command),
                response.payload.len()
            );
            for packet in response.packets() {
                device
                    .write(&packet)
                    .wrap_err("writing UHID input report")?;
                log::trace!("uhid tx packet_len={}", packet.len());
            }
        }

        match device.read() {
            Ok(OutputEvent::Output { data }) => {
                let Some((report, has_report_id_prefix)) = normalize_host_report(&data) else {
                    log::warn!("host -> authenticator: invalid-size len={}", data.len());
                    continue;
                };

                log::debug!(
                    "uhid rx report={}{}",
                    ctaphid::describe_report(report),
                    if has_report_id_prefix {
                        " report_id=0"
                    } else {
                        ""
                    }
                );
                if let Some(outcome) = ctaphid.handle_packet(report) {
                    let ctaphid::PacketOutcome::Response(response) = outcome else {
                        continue;
                    };
                    log::debug!(
                        "uhid tx cid={:#010x} command={} payload_len={}",
                        response.cid,
                        ctaphid::command_name(response.command),
                        response.payload.len()
                    );
                    for packet in response.packets() {
                        device
                            .write(&packet)
                            .wrap_err("writing UHID input report")?;
                        log::trace!("uhid tx packet_len={}", packet.len());
                    }
                }
            }
            Ok(OutputEvent::Start { .. }) => log::info!("uhid lifecycle event=start"),
            Ok(OutputEvent::Stop) => log::info!("uhid lifecycle event=stop"),
            Ok(OutputEvent::Open) => log::info!("uhid lifecycle event=open"),
            Ok(OutputEvent::Close) => log::info!("uhid lifecycle event=close"),
            Ok(OutputEvent::GetReport {
                id,
                report_number,
                report_type,
            }) => {
                log::debug!(
                    "uhid get_report id={id} report_number={report_number} report_type={report_type:?}"
                );
                device
                    .write_get_report_reply(id, 0, Vec::new())
                    .wrap_err("writing UHID get_report reply")?;
            }
            Ok(OutputEvent::SetReport {
                id,
                report_number,
                report_type,
                data,
            }) => {
                log::debug!(
                    "uhid set_report id={id} report_number={report_number} report_type={report_type:?} len={}",
                    data.len()
                );
                device
                    .write_set_report_reply(id, 0)
                    .wrap_err("writing UHID set_report reply")?;
            }
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(StreamError::Io(error)) => return Err(error).wrap_err("reading UHID event"),
            Err(StreamError::UnknownEventType(event_type)) => {
                log::warn!("unknown UHID event type: {event_type}");
            }
        }
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
            println!("{id}\t{rp_id}\t{user_name}\t{registered_at}\t{last_used_at}\t{pcr_indices}");
        }
    }
    Ok(())
}

fn base64_credential_id(id_hex: &str) -> Result<String> {
    Ok(STANDARD
        .encode(hex::decode(id_hex).wrap_err("decoding credential ID from daemon response")?))
}

fn run_update_passphrase() -> Result<()> {
    let old = prompt_password("Enter current daemon passphrase (leave empty if not set yet): ")
        .map_err(|e| eyre!("reading passphrase: {e}"))?;
    let old = if old.is_empty() { None } else { Some(old) };
    let new = prompt_password_confirm("Enter new daemon passphrase: ")?;
    let request = management::ManagementRequest::UpdatePassphrase {
        old_passphrase: old,
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
    let passphrase = prompt_password("Enter recovery passphrase: ")?;
    let response =
        management::send_request(&management::ManagementRequest::UnlockRecovery { passphrase })?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    println!("Recovery enrollment unlocked until daemon restart.");
    Ok(())
}

fn run_update_pcr_reference() -> Result<()> {
    let passphrase = prompt_password_confirm("Enter recovery passphrase: ")?;
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
    tpm::pcr_selection_for_indices(&args.pcr).wrap_err("invalid PCR selection")?;
    if args.all && !args.credential_ids.is_empty() {
        bail!("--all cannot be combined with credential IDs");
    }
    if !args.all && args.credential_ids.is_empty() {
        bail!("provide --all or at least one credential ID");
    }
    let passphrase = prompt_password_confirm("Enter recovery passphrase: ")?;

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
        tpm::pcr_selection_for_indices(&args.pcr_indices).wrap_err("invalid PCR selection")?;
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

fn prompt_password_confirm(prompt: &str) -> Result<String> {
    let pw = prompt_password(prompt).map_err(|e| eyre!("reading passphrase: {e}"))?;
    if pw.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(pw)
}

fn normalize_host_report(data: &[u8]) -> Option<(&[u8], bool)> {
    if data.len() == hid::REPORT_SIZE {
        Some((data, false))
    } else if data.len() == hid::REPORT_SIZE + 1 && data[0] == 0 {
        Some((&data[1..], true))
    } else {
        None
    }
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
    fn normalize_accepts_plain_report() {
        let data = [0u8; hid::REPORT_SIZE];
        let (report, has_prefix) = normalize_host_report(&data).expect("report");
        assert_eq!(report.len(), hid::REPORT_SIZE);
        assert!(!has_prefix);
    }

    #[test]
    fn normalize_strips_zero_report_id() {
        let data = [0u8; hid::REPORT_SIZE + 1];
        let (report, has_prefix) = normalize_host_report(&data).expect("report");
        assert_eq!(report.len(), hid::REPORT_SIZE);
        assert!(has_prefix);
    }

    #[test]
    fn normalize_rejects_nonzero_report_id() {
        let mut data = [0u8; hid::REPORT_SIZE + 1];
        data[0] = 1;
        assert!(normalize_host_report(&data).is_none());
    }
}
