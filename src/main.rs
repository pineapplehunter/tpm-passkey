use std::{
    env, path::PathBuf, sync::Arc, sync::atomic::AtomicBool, sync::mpsc, thread, time::Duration,
};

use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{WrapErr, bail, eyre},
};
use linux_tpm_fido2::{ctaphid, hid, management, session, store, tpm};
use rpassword::prompt_password;
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
    /// Set the default PCR policy for newly created credentials
    SetDefaultPcrPolicy(DefaultPcrPolicyArgs),
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
struct DefaultPcrPolicyArgs {
    /// PCR indices for the default policy (e.g. 1 7)
    pcr_indices: Vec<u32>,
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
        Command::SetDefaultPcrPolicy(args) => run_set_default_pcr_policy(args),
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

    log::info!("linux-tpm-fido2 starting");
    log::info!("uhid path: {}", args.uhid_path.display());
    log::info!("tpm path: {}", args.tpm_path.display());
    log::info!("dev store: {}", store_dir.display());
    log::info!(
        "credential database: {}",
        store::credentials_database_path_in_dir(&store_dir).display()
    );

    let session = session::SessionContext::detect();
    log::info!("session model: {}", session.describe());

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
        linux_tpm_fido2::ctap2::TpmCommand,
        mpsc::Sender<linux_tpm_fido2::ctap2::TpmCmdResult>,
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
            log::debug!("processing TPM command from management thread");
            let result = ctaphid
                .handle_tpm_command(command)
                .map_err(|e| format!("{e}"));
            if resp_tx.send(result).is_err() {
                log::warn!("management thread dropped response channel");
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
            let id = management::value_get(cred, "id")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            let rp_id = management::value_get(cred, "rp_id")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            let user_name = management::value_get(cred, "user_name")
                .and_then(|v| v.as_text())
                .unwrap_or("");
            println!("{id}\t{rp_id}\t{user_name}");
        }
    }
    Ok(())
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

fn run_set_default_pcr_policy(args: DefaultPcrPolicyArgs) -> Result<()> {
    tpm::pcr_selection_for_indices(&args.pcr_indices).wrap_err("invalid PCR selection")?;
    let pcr_indices = args.pcr_indices.clone();
    let request = management::ManagementRequest::SetDefaultPcrPolicy { pcr_indices };
    let response = management::send_request(&request)?;
    if !response.ok {
        bail!("daemon error: {}", response.error.unwrap_or_default());
    }
    println!("default PCR policy set to {:?}", args.pcr_indices);
    Ok(())
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
