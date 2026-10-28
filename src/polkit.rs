use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use color_eyre::Result;
use zbus::{Connection, zvariant::Value};

use crate::approval::{ApprovalControl, ApprovalOutcome, DEFAULT_APPROVAL_TIMEOUT};

const POLKIT_AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const POLKIT_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_ACTION_ID: &str = "io.github.pineapplehunter.tpm-passkey.approve";
const CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_millis(100);
static NEXT_CANCELLATION_ID: AtomicU64 = AtomicU64::new(1);

/// Compatibility entry point, bounded by the default action timeout.
pub fn check_active_session() -> Result<bool> {
    crate::approval::runtime()?.block_on(async {
        let control = ApprovalControl::new(None, Instant::now() + DEFAULT_APPROVAL_TIMEOUT);
        Ok(check_active_session_controlled(&control).await? == ApprovalOutcome::Approved)
    })
}

/// Route UP to the desktop's polkit agent, not an identity or built-in UV check.
///
/// Err means the bus/polkit service is unavailable and terminal fallback is
/// permitted. Denials, malformed replies, and unroutable sessions fail closed.
/// Connection setup AND logind lookup are inside the same controlled workflow.
pub async fn check_active_session_controlled(control: &ApprovalControl) -> Result<ApprovalOutcome> {
    let cancellation_id = format!(
        "tpm-passkey-{}-{}",
        std::process::id(),
        NEXT_CANCELLATION_ID.fetch_add(1, Ordering::Relaxed)
    );
    let mut connection = None;
    let mut request_started = false;
    let result = control
        .run(async {
            connection = Some(connect_bus(zbus::Address::system()?).await?);
            let connection = connection.as_ref().expect("connection just established");
            let (pid, user_uid) = match crate::systemd_logind::approval_subject(connection).await {
                Ok(Some(subject)) => subject,
                subject => {
                    log::warn!("no usable logind subject for polkit: {subject:?}");
                    return Ok(ApprovalOutcome::Denied);
                }
            };
            let start_time = match process_start_time_ticks(pid) {
                Ok(start_time) => start_time,
                Err(error) => {
                    log::warn!("cannot read polkit subject start time: {error:?}");
                    return Ok(ApprovalOutcome::Denied);
                }
            };
            let mut subject_details: HashMap<&str, Value> = HashMap::new();
            subject_details.insert("pid", Value::from(pid));
            subject_details.insert("start-time", Value::from(start_time));
            subject_details.insert("uid", Value::from(user_uid as i32));
            let subject = ("unix-process", subject_details);
            let details: HashMap<&str, &str> = HashMap::new();
            // AllowUserInteraction = 0x1 — lets polkit show an auth dialog.
            request_started = true;
            let reply = connection
                .call_method(
                    Some(POLKIT_AUTHORITY),
                    POLKIT_AUTHORITY_PATH,
                    Some(POLKIT_AUTHORITY_IFACE),
                    "CheckAuthorization",
                    &(subject, POLKIT_ACTION_ID, details, 1u32, &cancellation_id),
                )
                .await;
            match reply {
                Ok(reply) => {
                    let result: zbus::Result<(bool, bool, HashMap<String, String>)> =
                        reply.body().deserialize();
                    match result {
                        Ok((true, _, _)) => Ok(ApprovalOutcome::Approved),
                        Ok((false, _, _)) => Ok(ApprovalOutcome::Denied),
                        Err(error) => {
                            log::warn!("invalid polkit reply: {error:?}");
                            Ok(ApprovalOutcome::Denied)
                        }
                    }
                }
                Err(error) if service_unavailable(&error) => Err(error.into()),
                Err(error) => {
                    log::warn!("polkit authorization failed: {error:?}");
                    Ok(ApprovalOutcome::Denied)
                }
            }
        })
        .await;

    match result {
        Ok(result) => result,
        Err(outcome) => {
            if request_started && let Some(connection) = &connection {
                // Same unique bus sender and ID as CheckAuthorization. Cleanup
                // has a small separate allowance after the action budget ends.
                cancel_request(connection, &cancellation_id).await;
            }
            Ok(outcome)
        }
    }
}

/// Avoid zbus's address connector: even its tokio backend currently performs
/// Unix connect via spawn_blocking, whose shutdown can outlive cancellation.
/// Only local Unix system buses are supported; no DNS, subprocesses or nonce I/O.
async fn connect_bus(address: zbus::Address) -> zbus::Result<Connection> {
    use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
    use zbus::address::transport::{Transport, UnixSocket};

    let Transport::Unix(unix) = address.transport() else {
        return Err(zbus::Error::Unsupported);
    };
    let socket_address = match unix.path() {
        UnixSocket::File(path) => SocketAddr::from_pathname(path)?,
        UnixSocket::Abstract(name) => SocketAddr::from_abstract_name(name.as_encoded_bytes())?,
        _ => return Err(zbus::Error::Unsupported),
    };
    let stream = tokio::net::UnixStream::connect_addr(&socket_address.into()).await?;
    let connection = zbus::connection::Builder::unix_stream(stream)
        .build()
        .await?;
    if let Some(guid) = address.guid()
        && connection.server_guid().as_str() != guid.as_str()
    {
        return Err(zbus::Error::Handshake("system bus GUID mismatch".into()));
    }
    Ok(connection)
}

fn service_unavailable(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::InputOutput(_) => true,
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
        ),
        _ => false,
    }
}

async fn cancel_request(connection: &Connection, cancellation_id: &str) {
    let _ = tokio::time::timeout(
        CANCEL_CLEANUP_TIMEOUT,
        connection.call_method(
            Some(POLKIT_AUTHORITY),
            POLKIT_AUTHORITY_PATH,
            Some(POLKIT_AUTHORITY_IFACE),
            "CancelCheckAuthorization",
            &(cancellation_id,),
        ),
    )
    .await;
}

/// Read the process start time in clock ticks since boot from local procfs.
fn process_start_time_ticks(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_comm = stat
        .rfind(')')
        .ok_or_else(|| color_eyre::eyre::eyre!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat[after_comm + 2..].split_whitespace().collect();
    fields
        .get(19)
        .ok_or_else(|| color_eyre::eyre::eyre!("missing starttime in /proc/{pid}/stat"))?
        .parse()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        future::pending,
        os::{
            linux::net::SocketAddrExt,
            unix::net::{SocketAddr, UnixListener},
        },
        sync::{Arc, atomic::AtomicBool},
    };

    fn stalled_bus() -> (tokio::net::UnixListener, zbus::Address) {
        let name = format!(
            "tpm-passkey-test-{}-{}",
            std::process::id(),
            NEXT_CANCELLATION_ID.fetch_add(1, Ordering::Relaxed)
        );
        let listener =
            UnixListener::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        listener.set_nonblocking(true).unwrap();
        (
            tokio::net::UnixListener::from_std(listener).unwrap(),
            format!("unix:abstract={name}").parse().unwrap(),
        )
    }

    #[test]
    fn stalled_bus_handshake_is_cancelled_while_pending() {
        crate::approval::runtime().unwrap().block_on(async {
            let (listener, address) = stalled_bus();
            let flag = Arc::new(AtomicBool::new(false));
            let control =
                ApprovalControl::new(Some(flag.clone()), Instant::now() + Duration::from_secs(2));
            let accepted = Cell::new(false);
            let cancelled_at = Cell::new(None);
            // Accept the actual connection but never answer the authentication
            // handshake. No background task/thread survives this test's scope.
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                accepted.set(true);
                tokio::time::sleep(Duration::from_millis(30)).await;
                flag.store(true, Ordering::Relaxed);
                cancelled_at.set(Some(Instant::now()));
                pending::<()>().await;
                drop(stream);
            };
            tokio::select! {
                result = control.run(connect_bus(address)) => {
                    assert!(matches!(result, Err(ApprovalOutcome::Cancelled)));
                    assert!(accepted.get());
                    assert!(cancelled_at.get().unwrap().elapsed() < Duration::from_millis(200));
                }
                () = server => unreachable!(),
            }
        });
    }

    #[test]
    fn stalled_bus_handshake_observes_deadline() {
        crate::approval::runtime().unwrap().block_on(async {
            let (listener, address) = stalled_bus();
            let control = ApprovalControl::new(None, Instant::now() + Duration::from_millis(60));
            let accepted = Cell::new(false);
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                accepted.set(true);
                pending::<()>().await;
                drop(stream);
            };
            tokio::select! {
                result = control.run(connect_bus(address)) => {
                    assert!(matches!(result, Err(ApprovalOutcome::TimedOut)));
                    assert!(accepted.get());
                    assert!(Instant::now().duration_since(control.deadline) < Duration::from_millis(200));
                }
                () = server => unreachable!(),
            }
        });
    }

    #[test]
    fn only_transport_or_missing_service_is_unavailable() {
        assert!(service_unavailable(&zbus::Error::InputOutput(Arc::new(
            std::io::Error::from(std::io::ErrorKind::BrokenPipe)
        ))));
        assert!(!service_unavailable(&zbus::Error::InvalidReply));
        assert!(!service_unavailable(&zbus::Error::Failure("denied".into())));
    }
}
