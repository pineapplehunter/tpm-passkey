use clap::Parser;
use color_eyre::{
    Result,
    eyre::{WrapErr, bail},
};
use std::{env, path::PathBuf, sync::mpsc, thread, time::Duration};
use tpm_passkey::{bus, ctaphid, hid, store, tpm};
use uhid_virt::{OutputEvent, StreamError, UHIDDevice};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Linux TPM-backed FIDO2/WebAuthn authenticator daemon"
)]
struct Cli {
    /// Path to the Linux UHID character device
    #[arg(long, default_value = "/dev/uhid")]
    uhid_path: PathBuf,
    /// Path to the TPM resource-manager device
    #[arg(long, default_value = "/dev/tpmrm0")]
    tpm_path: PathBuf,
    /// Directory for TPM-backed credentials
    #[arg(long, default_value = store::DEV_STORE_DIR)]
    store_dir: PathBuf,
    /// Only print resolved configuration; do not open devices or the bus
    #[arg(long)]
    dry_run: bool,
}
fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    run_daemon(Cli::parse())
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
fn run_daemon(args: Cli) -> Result<()> {
    let store_dir = absolute_path(&args.store_dir);
    log::info!("tpm-passkey-daemon starting");
    log::info!("uhid path: {}", args.uhid_path.display());
    log::info!("tpm path: {}", args.tpm_path.display());
    log::info!("store: {}", store_dir.display());
    log::info!(
        "credential database: {}",
        store::credentials_database_path_in_dir(&store_dir).display()
    );
    if args.dry_run {
        log::info!("dry run: not opening UHID, TPM or system bus");
        return Ok(());
    }
    // The well-known bus endpoint is a privileged service, not a desktop tool.
    if unsafe { libc::geteuid() } != 0 {
        bail!("tpm-passkey-daemon must run as root");
    }
    if let Err(error) = tpm::check_device(&args.tpm_path) {
        log::warn!(
            "TPM device {} is not accessible yet: {error}",
            args.tpm_path.display()
        );
    }
    let (tpm_cmd_tx, tpm_cmd_rx) = mpsc::channel::<(
        tpm_passkey::ctap2::TpmCommand,
        mpsc::Sender<tpm_passkey::ctap2::TpmCmdResult>,
    )>();
    let approval = bus::start(store_dir.clone(), tpm_cmd_tx)?;
    let mut device = UHIDDevice::create_with_path(hid::create_params(), &args.uhid_path)
        .wrap_err_with(|| format!("opening UHID device {}", args.uhid_path.display()))?;
    let mut ctaphid = ctaphid::PacketHandler::new_with_user_approval(
        store_dir,
        Some(args.tpm_path.clone()),
        Box::new(approval.clone()),
    );
    log::info!("created virtual FIDO HID device; waiting for host reports");
    loop {
        if !approval.healthy() {
            bail!("privileged system bus service disconnected");
        }
        if let Ok((command, resp_tx)) = tpm_cmd_rx.try_recv() {
            ctaphid.queue_tpm_command(command, resp_tx);
        }
        if let Some(ctaphid::PacketOutcome::Response(response)) = ctaphid.poll() {
            for packet in response.packets() {
                device
                    .write(&packet)
                    .wrap_err("writing UHID input report")?;
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
                if let Some(ctaphid::PacketOutcome::Response(response)) =
                    ctaphid.handle_packet(report)
                {
                    for packet in response.packets() {
                        device
                            .write(&packet)
                            .wrap_err("writing UHID input report")?;
                    }
                }
            }
            Ok(OutputEvent::Start { .. }) => log::info!("uhid lifecycle event=start"),
            Ok(OutputEvent::Stop) => log::info!("uhid lifecycle event=stop"),
            Ok(OutputEvent::Open) => log::info!("uhid lifecycle event=open"),
            Ok(OutputEvent::Close) => log::info!("uhid lifecycle event=close"),
            Ok(OutputEvent::GetReport { id, .. }) => {
                device
                    .write_get_report_reply(id, 0, Vec::new())
                    .wrap_err("writing UHID get_report reply")?;
            }
            Ok(OutputEvent::SetReport { id, .. }) => {
                device
                    .write_set_report_reply(id, 0)
                    .wrap_err("writing UHID set_report reply")?;
            }
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(StreamError::Io(error)) => return Err(error).wrap_err("reading UHID event"),
            Err(StreamError::UnknownEventType(event_type)) => {
                log::warn!("unknown UHID event type: {event_type}")
            }
        }
    }
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
    fn standalone_daemon_cli_retains_dry_run() {
        assert!(
            Cli::try_parse_from(["tpm-passkey-daemon", "--dry-run"])
                .unwrap()
                .dry_run
        );
        assert!(Cli::try_parse_from(["tpm-passkey-daemon", "list-credentials"]).is_err());
    }
    #[test]
    fn normalize_accepts_plain_report() {
        let data = [0u8; hid::REPORT_SIZE];
        let (report, has_prefix) = normalize_host_report(&data).unwrap();
        assert_eq!(report.len(), hid::REPORT_SIZE);
        assert!(!has_prefix);
    }
    #[test]
    fn normalize_strips_zero_report_id() {
        let data = [0u8; hid::REPORT_SIZE + 1];
        let (report, has_prefix) = normalize_host_report(&data).unwrap();
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
