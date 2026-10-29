use crate::model::{MAX_TIMEOUT, Shared};
use color_eyre::{Result, eyre::eyre};
use futures_util::StreamExt;
use std::time::{Duration, Instant};
use tpm_passkey_protocol::{AGENT_PATH, ApprovalContext, BUS_NAME, DAEMON_IFACE, DAEMON_PATH};
use zbus::{Connection, fdo::DBusProxy, message::Header};

#[derive(Clone)]
struct Agent {
    connection: Connection,
    shared: Shared,
}

struct Ticket {
    shared: Shared,
    token: u64,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.shared.discard(self.token);
    }
}

/// The bus daemon supplies both unique-name ownership and Unix credentials.
/// A UID/name supplied by a method caller is never an authentication input.
async fn root_owner(connection: &Connection) -> Result<Option<String>> {
    let proxy = DBusProxy::new(connection).await?;
    let name = BUS_NAME.try_into()?;
    let owner = match proxy.get_name_owner(name).await {
        Ok(owner) => owner,
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if proxy
        .get_connection_unix_user(owner.as_str().try_into()?)
        .await?
        != 0
    {
        return Ok(None);
    }
    // Do not install a stale owner if ownership changed while credentials were
    // being checked. The monitor also processes every queued ownership change.
    if proxy.get_name_owner(BUS_NAME.try_into()?).await? != owner {
        return Ok(None);
    }
    Ok(Some(owner.to_string()))
}

async fn caller_is_daemon(connection: &Connection, sender: &str) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(1), root_owner(connection)).await,
        Ok(Ok(Some(owner))) if owner == sender)
}

// Literal must stay equal to protocol::AGENT_IFACE (checked by a test).
#[zbus::interface(name = "io.github.pineapplehunter.TpmPasskey1.ApprovalAgent")]
impl Agent {
    async fn request(
        &self,
        id: String,
        context: ApprovalContext,
        timeout_ms: u32,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let Some(sender) = header.sender().map(|s| s.as_str().to_owned()) else {
            return false;
        };
        if timeout_ms == 0 || Duration::from_millis(timeout_ms.into()) > MAX_TIMEOUT {
            return false;
        }
        // Capture the deadline before any bus or UI wait. It is never restarted.
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.into());
        tokio::time::timeout_at(deadline.into(), async {
            if !caller_is_daemon(&self.connection, &sender).await {
                return false;
            }
            let Some((token, answer)) = self.shared.begin(&sender, &id, context, deadline) else {
                return false;
            };
            let _ticket = Ticket {
                shared: self.shared.clone(),
                token,
            };
            if !answer.await.unwrap_or(false) {
                return false;
            }
            let authenticated = caller_is_daemon(&self.connection, &sender).await;
            self.shared.complete(token, &sender, authenticated)
        })
        .await
        .unwrap_or(false)
    }

    async fn cancel(&self, id: String, #[zbus(header)] header: Header<'_>) {
        let Some(sender) = header.sender().map(|s| s.as_str().to_owned()) else {
            return;
        };
        if caller_is_daemon(&self.connection, &sender).await {
            self.shared.cancel(&sender, &id);
        }
    }
}

async fn monitor(connection: &Connection, shared: &Shared) -> Result<()> {
    let proxy = DBusProxy::new(connection).await?;
    // Install the signal subscription before resolving the initial owner.
    let mut changes = proxy
        .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
        .await?;
    shared.set_owner(tokio::time::timeout(Duration::from_secs(1), root_owner(connection)).await??);
    while let Some(_change) = changes.next().await {
        // Invalidate first, including accepted-but-not-yet-returned decisions.
        // A restart/reacquisition can register again but cannot reuse consent.
        shared.set_owner(None);
        shared.set_owner(
            tokio::time::timeout(Duration::from_secs(1), root_owner(connection)).await??,
        );
    }
    Err(eyre!("system bus ownership monitor disconnected"))
}

async fn register(connection: &Connection, shared: &Shared) {
    let mut changes = shared.subscribe();
    let mut retry = tokio::time::interval(Duration::from_secs(2));
    let mut registered = None;
    loop {
        tokio::select! {
            _ = retry.tick() => {},
            result = changes.changed() => { if result.is_err() { return; } },
        }
        let (owner, epoch) = shared.owner();
        let Some(owner) = owner else {
            registered = None;
            continue;
        };
        // Retry failures, but do not repeat successful registrations.
        if registered == Some(epoch) || shared.has_pending() {
            continue;
        }
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let path = zbus::zvariant::ObjectPath::try_from(AGENT_PATH)?;
            let reply = connection
                .call_method(
                    Some(owner.as_str()),
                    DAEMON_PATH,
                    Some(DAEMON_IFACE),
                    "RegisterAgent",
                    &(path,),
                )
                .await?;
            reply.body().deserialize::<()>()
        })
        .await;
        match result {
            Ok(Ok(())) if shared.owner() == (Some(owner), epoch) => {
                if registered != Some(epoch) {
                    tracing::info!("registered graphical approval agent");
                }
                registered = Some(epoch);
            }
            _ => tracing::debug!("approval agent registration unavailable; retrying"),
        }
    }
}

async fn session(shared: &Shared) -> Result<()> {
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        tpm_passkey_protocol::transport::connect_system_bus(),
    )
    .await??;
    let result = async {
        connection
            .object_server()
            .at(
                AGENT_PATH,
                Agent {
                    connection: connection.clone(),
                    shared: shared.clone(),
                },
            )
            .await?;
        tokio::select! {
            result = monitor(&connection, shared) => result,
            _ = register(&connection, shared) => Err(eyre!("approval registration stopped")),
            _ = connection.closed() => Err(eyre!("system bus disconnected")),
        }
    }
    .await;
    shared.set_owner(None);
    // Explicitly close all connection clones, including the exported object.
    let _ = tokio::time::timeout(Duration::from_secs(1), connection.close()).await;
    result
}

pub fn start(shared: Shared) -> Result<()> {
    std::thread::Builder::new()
        .name("approval-system-bus".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "cannot create bus runtime");
                    return;
                }
            };
            runtime.block_on(async {
                loop {
                    if let Err(error) = session(&shared).await {
                        tracing::warn!(%error, "approval service unavailable; consent denied");
                    }
                    shared.set_owner(None);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;
    #[test]
    fn exported_interface_matches_shared_protocol() {
        assert_eq!(Agent::name().as_str(), tpm_passkey_protocol::AGENT_IFACE);
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session as a non-root user"]
    async fn nonroot_bus_owner_cannot_request_or_cancel_approval() {
        let agent = Connection::session().await.unwrap();
        let caller = Connection::session().await.unwrap();
        caller.request_name(BUS_NAME).await.unwrap();
        let proxy = DBusProxy::new(&agent).await.unwrap();
        let owner = caller.unique_name().unwrap().as_str();
        assert_ne!(
            proxy
                .get_connection_unix_user(owner.try_into().unwrap())
                .await
                .unwrap(),
            0
        );
        let (sender, _events) = async_channel::bounded(16);
        let shared = Shared::new(sender);
        // Even a matching cached name is insufficient: credentials and current
        // well-known-name ownership are checked with the bus on every call.
        shared.set_owner(Some(owner.into()));
        agent
            .object_server()
            .at(
                AGENT_PATH,
                Agent {
                    connection: agent.clone(),
                    shared: shared.clone(),
                },
            )
            .await
            .unwrap();
        let context = ApprovalContext {
            operation: "login".into(),
            rp_id: "example.org".into(),
            rp_name: String::new(),
            account_name: String::new(),
            account_id: String::new(),
            credential_count: 1,
        };
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            caller.call_method(
                Some(agent.unique_name().unwrap().as_str()),
                AGENT_PATH,
                Some(tpm_passkey_protocol::AGENT_IFACE),
                "Request",
                &("untrusted", context.clone(), 1000u32),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!reply.body().deserialize::<bool>().unwrap());
        let (token, _) = shared
            .begin(
                owner,
                "pending",
                context,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            caller.call_method(
                Some(agent.unique_name().unwrap().as_str()),
                AGENT_PATH,
                Some(tpm_passkey_protocol::AGENT_IFACE),
                "Cancel",
                &("pending",),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        reply.body().deserialize::<()>().unwrap();
        assert!(shared.active(token));
        shared.set_owner(None);
        agent.close().await.unwrap();
        caller.close().await.unwrap();
    }
}
