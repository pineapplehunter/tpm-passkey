use color_eyre::Result;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

mod protocol;
mod service;

pub use protocol::{CredentialTarget, ManagementRequest, ManagementResponse, value_get};
use service::dispatch;

use crate::ctap2;

/// Returns the well-known path for the management Unix socket.
pub fn management_socket_path() -> PathBuf {
    PathBuf::from("/run/linux-tpm-fido2/management.sock")
}

fn recv_message(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn send_message(stream: &mut UnixStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn handle_client(
    mut stream: UnixStream,
    store_dir: PathBuf,
    tpm_cmd_tx: Option<ctap2::TpmCmdSender>,
) {
    let data = match recv_message(&mut stream) {
        Ok(d) => Zeroizing::new(d),
        Err(e) => {
            log::warn!("management: failed to read request: {e}");
            return;
        }
    };

    let request: ManagementRequest = match ciborium::from_reader(&data[..]) {
        Ok(r) => r,
        Err(e) => {
            let resp = ManagementResponse {
                ok: false,
                error: Some(format!("invalid request: {e}")),
                result: None,
            };
            let mut encoded = Vec::new();
            if ciborium::into_writer(&resp, &mut encoded).is_ok() {
                let _ = send_message(&mut stream, &encoded);
            }
            return;
        }
    };

    let response = dispatch(&store_dir, tpm_cmd_tx.as_ref(), &request);
    let mut encoded = Vec::new();
    if let Err(e) = ciborium::into_writer(&response, &mut encoded) {
        log::warn!("management: failed to encode response: {e}");
        return;
    }
    if let Err(e) = send_message(&mut stream, &encoded) {
        log::warn!("management: failed to send response: {e}");
    }
}

pub fn serve(
    store_dir: PathBuf,
    tpm_cmd_tx: Option<ctap2::TpmCmdSender>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let socket_path = management_socket_path();

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).map_err(|e| {
        color_eyre::eyre::eyre!("binding management socket at {socket_path:?}: {e}")
    })?;

    // Restrict the socket to root-only access.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700))?;

    log::info!("management socket at {}", socket_path.display());

    listener.set_nonblocking(true)?;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, addr)) => {
                log::debug!("management: connection from {addr:?}");
                let store_dir = store_dir.clone();
                let tpm_cmd_tx = tpm_cmd_tx.clone();
                std::thread::spawn(move || {
                    handle_client(stream, store_dir, tpm_cmd_tx);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                log::warn!("management: accept error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

pub fn send_request(request: &ManagementRequest) -> Result<ManagementResponse> {
    let socket_path = management_socket_path();

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        color_eyre::eyre::eyre!(
            "connecting to daemon at {socket_path:?}: {e}. Is the daemon running?"
        )
    })?;

    let mut encoded = Zeroizing::new(Vec::new());
    ciborium::into_writer(request, &mut *encoded)
        .map_err(|e| color_eyre::eyre::eyre!("encoding request: {e}"))?;

    send_message(&mut stream, &encoded)
        .map_err(|e| color_eyre::eyre::eyre!("sending request: {e}"))?;

    let response_data = recv_message(&mut stream)
        .map_err(|e| color_eyre::eyre::eyre!("receiving response: {e}"))?;

    let response: ManagementResponse = ciborium::from_reader(&response_data[..])
        .map_err(|e| color_eyre::eyre::eyre!("decoding response: {e}"))?;

    Ok(response)
}
