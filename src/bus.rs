//! Persistent privileged system-bus endpoint and transaction-bound GTK presence.
use crate::{
    approval::{ApprovalControl, ApprovalOutcome, DEFAULT_APPROVAL_TIMEOUT, UserApproval},
    ctap2,
    systemd_logind::{self, Session},
};
use color_eyre::{Result, eyre::eyre};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tpm_passkey_protocol::{self as wire, ApprovalContext};
use zbus::{
    Connection, MessageStream,
    export::futures_core::Stream,
    zvariant::{OwnedFd, OwnedObjectPath, OwnedValue},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Agent {
    sender: String,
    path: OwnedObjectPath,
    session: Session,
}
#[derive(Default)]
struct Registry {
    generation: u64,
    logind_owner: Option<String>,
    agent: Option<Agent>,
    registering: HashMap<String, usize>,
    pending: Option<(String, Arc<AtomicBool>)>,
    failed: bool,
}
impl Registry {
    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.agent = None;
        if let Some((_, cancelled)) = &self.pending {
            cancelled.store(true, Ordering::SeqCst);
        }
    }
    fn owner_lost(&mut self, name: &str) {
        if self
            .agent
            .as_ref()
            .is_some_and(|agent| agent.sender == name)
        {
            self.invalidate();
        } else if self.registering.contains_key(name) {
            // A candidate can disappear after NameHasOwner but before commit.
            // Preserve any unrelated live agent while invalidating its snapshot.
            self.generation = self.generation.wrapping_add(1);
        }
    }
    fn register(&mut self, generation: u64, agent: Agent) -> bool {
        if self.failed || self.generation != generation || self.pending.is_some() {
            return false;
        }
        if let Some(existing) = &self.agent {
            return existing == &agent;
        }
        self.agent = Some(agent);
        true
    }
    fn begin(&mut self, id: String) -> Option<(Agent, Arc<AtomicBool>)> {
        if self.failed || self.pending.is_some() {
            return None;
        }
        let agent = self.agent.clone()?;
        let cancelled = Arc::new(AtomicBool::new(false));
        self.pending = Some((id, cancelled.clone()));
        Some((agent, cancelled))
    }
    fn finish(&mut self, id: &str) {
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending, _)| pending == id)
        {
            self.pending = None;
        }
    }
}

#[derive(Clone)]
pub struct BusApproval {
    connection: Connection,
    registry: Arc<Mutex<Registry>>,
    barrier: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
}
struct Registration {
    registry: Arc<Mutex<Registry>>,
    sender: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap();
        if let Some(count) = registry.registering.get_mut(&self.sender) {
            *count -= 1;
            if *count == 0 {
                registry.registering.remove(&self.sender);
            }
        }
    }
}
struct Pending {
    registry: Arc<Mutex<Registry>>,
    id: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.registry.lock().unwrap().finish(&self.id);
    }
}
impl UserApproval for BusApproval {
    fn approve(&self, _: &str) -> bool {
        false
    }
    fn approve_context_controlled(
        &self,
        context: &ApprovalContext,
        control: &ApprovalControl,
    ) -> ApprovalOutcome {
        if let Some(stopped) = control.stopped() {
            return stopped;
        }
        if !context.validate() {
            return ApprovalOutcome::Denied;
        }
        let mut random = [0; 32];
        if getrandom::fill(&mut random).is_err() {
            return ApprovalOutcome::Denied;
        }
        let id = hex::encode(random);
        let Some((agent, invalid)) = self.registry.lock().unwrap().begin(id.clone()) else {
            return ApprovalOutcome::Denied;
        };
        let _pending = Pending {
            registry: self.registry.clone(),
            id: id.clone(),
        };
        let Ok(runtime) = crate::approval::runtime() else {
            return ApprovalOutcome::Denied;
        };
        runtime.block_on(async {
            let mut requested = false;
            let result = control
                .run(async {
                    let workflow = async {
                        if !self.eligible(&agent).await || invalid.load(Ordering::SeqCst) {
                            return false;
                        }
                        let remaining = control.deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return false;
                        }
                        // Round up so helper expiry cannot race a fraction of
                        // a millisecond ahead of the authoritative CTAP deadline
                        // and turn USER_ACTION_TIMEOUT into a denial.
                        let remaining = remaining
                            .as_millis()
                            .saturating_add(1)
                            .min(DEFAULT_APPROVAL_TIMEOUT.as_millis())
                            as u32;
                        requested = true;
                        let reply = self
                            .connection
                            .call_method(
                                Some(agent.sender.as_str()),
                                agent.path.as_str(),
                                Some(wire::AGENT_IFACE),
                                "Request",
                                &(&id, context, remaining),
                            )
                            .await;
                        let allowed = reply
                            .ok()
                            .and_then(|reply| reply.body().deserialize::<bool>().ok())
                            .unwrap_or(false);
                        allowed && self.eligible(&agent).await && !invalid.load(Ordering::SeqCst)
                    };
                    tokio::pin!(workflow);
                    loop {
                        tokio::select! {
                            biased;
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                                if invalid.load(Ordering::SeqCst) { return false; }
                            }
                            result = &mut workflow => return result,
                        }
                    }
                })
                .await;
            if requested && !matches!(result, Ok(true)) {
                // Cleanup can only dismiss this exact ID, never another request.
                let _ = tokio::time::timeout(
                    Duration::from_millis(100),
                    self.connection.call_method(
                        Some(agent.sender.as_str()),
                        agent.path.as_str(),
                        Some(wire::AGENT_IFACE),
                        "Cancel",
                        &(&id,),
                    ),
                )
                .await;
            }
            match result {
                Ok(true) if !invalid.load(Ordering::SeqCst) => {
                    control.stopped().unwrap_or(ApprovalOutcome::Approved)
                }
                Ok(_) => ApprovalOutcome::Denied,
                Err(outcome) => outcome,
            }
        })
    }
}
impl BusApproval {
    async fn eligible(&self, agent: &Agent) -> bool {
        let eligible = crate::polkit::caller_alive(&self.connection, &agent.sender).await
            && systemd_logind::eligible_session(&self.connection)
                .await
                .ok()
                .flatten()
                .as_ref()
                == Some(&agent.session);
        let eligible = eligible && self.observations_current().await;
        let mut registry = self.registry.lock().unwrap();
        if !eligible && registry.agent.as_ref() == Some(agent) {
            registry.invalidate();
        }
        eligible && registry.agent.as_ref() == Some(agent)
    }
    async fn observations_current(&self) -> bool {
        // The connection reader enqueues signals before delivering subsequent
        // query replies. Drain those observations before accepting a snapshot;
        // a lock/unlock pair must not disappear behind a successful GetAll.
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.barrier.send(tx).await.is_ok() && rx.await.is_ok()
    }
    pub fn healthy(&self) -> bool {
        !self.registry.lock().unwrap().failed
    }
}

pub(crate) fn management_action(operation: &str) -> Option<&'static str> {
    match operation {
        "list-credentials" | "show-config" => Some(wire::ACTION_READ),
        "update-passphrase" | "unlock-recovery" | "update-pcr-reference" | "update-pcr-policy" => {
            Some(wire::ACTION_RECOVERY)
        }
        "set-default-pcr-policy" | "disable-default-pcr-policy" => Some(wire::ACTION_SETTINGS),
        _ => None,
    }
}
fn denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied("request denied".into())
}
fn sender(header: &zbus::message::Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(|s| s.as_str().to_owned())
        .filter(|s| s.starts_with(':'))
        .ok_or_else(denied)
}
fn control() -> ApprovalControl {
    ApprovalControl::new(None, Instant::now() + DEFAULT_APPROVAL_TIMEOUT)
}

struct Daemon {
    approval: BusApproval,
    store_dir: std::path::PathBuf,
    tpm: ctap2::TpmCmdSender,
    management_busy: Arc<AtomicBool>,
}
#[zbus::interface(name = "io.github.pineapplehunter.TpmPasskey1")]
impl Daemon {
    async fn register_agent(
        &self,
        path: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let sender = sender(&header)?;
        if path.as_str() != wire::AGENT_PATH {
            return Err(denied());
        }
        let control = control();
        let generation = {
            let mut registry = self.approval.registry.lock().unwrap();
            if registry.failed
                || registry.pending.is_some()
                || registry
                    .agent
                    .as_ref()
                    .is_some_and(|a| a.sender != sender || a.path != path)
            {
                return Err(denied());
            }
            *registry.registering.entry(sender.clone()).or_default() += 1;
            registry.generation
        };
        let _registration = Registration {
            registry: self.approval.registry.clone(),
            sender: sender.clone(),
        };
        if !crate::polkit::authorize(
            &self.approval.connection,
            &sender,
            wire::ACTION_REGISTER,
            false,
            &control,
        )
        .await
        .unwrap_or(false)
        {
            return Err(denied());
        }
        control
            .run(async {
                let session = systemd_logind::eligible_session(&self.approval.connection)
                    .await
                    .ok()
                    .flatten()
                    .ok_or_else(denied)?;
                let proxy = zbus::fdo::DBusProxy::new(&self.approval.connection)
                    .await
                    .map_err(|_| denied())?;
                let uid = proxy
                    .get_connection_unix_user(sender.as_str().try_into().map_err(|_| denied())?)
                    .await
                    .map_err(|_| denied())?;
                if uid != session.uid
                    || !crate::polkit::caller_alive(&self.approval.connection, &sender).await
                    || systemd_logind::eligible_session(&self.approval.connection)
                        .await
                        .ok()
                        .flatten()
                        .as_ref()
                        != Some(&session)
                    || !self.approval.observations_current().await
                {
                    return Err(denied());
                }
                if self.approval.registry.lock().unwrap().register(
                    generation,
                    Agent {
                        sender,
                        path,
                        session,
                    },
                ) {
                    Ok(())
                } else {
                    Err(denied())
                }
            })
            .await
            .map_err(|_| denied())?
    }

    async fn unregister_agent(
        &self,
        path: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let sender = sender(&header)?;
        let mut registry = self.approval.registry.lock().unwrap();
        if registry
            .agent
            .as_ref()
            .is_some_and(|a| a.sender == sender && a.path == path)
        {
            registry.invalidate();
            Ok(())
        } else {
            Err(denied())
        }
    }

    async fn manage(
        &self,
        operation: String,
        request: OwnedFd,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let sender = sender(&header)?;
        let action = management_action(&operation).ok_or_else(denied)?;
        let control = control();
        // This MUST precede descriptor inspection, decoding and secret reads.
        if !crate::polkit::authorize(&self.approval.connection, &sender, action, true, &control)
            .await
            .unwrap_or(false)
        {
            return Err(denied());
        }
        control
            .run(async {
                if !crate::polkit::caller_alive(&self.approval.connection, &sender).await {
                    return Err(denied());
                }
                let request = wire::transport::read_request(&request).map_err(|_| denied())?;
                if request.operation() != operation {
                    return Err(denied());
                }
                if self
                    .management_busy
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    return Err(zbus::fdo::Error::LimitsExceeded(
                        "management request already running".into(),
                    ));
                }
                let busy = Busy(self.management_busy.clone());
                let dir = self.store_dir.clone();
                let tpm = self.tpm.clone();
                let deadline = control.deadline;
                let task = tokio::task::spawn_blocking(move || {
                    let _busy = busy;
                    let response =
                        crate::management::dispatch_until(&dir, Some(&tpm), &request, deadline);
                    let mut encoded = Vec::new();
                    ciborium::into_writer(&response, &mut encoded).map_err(|_| denied())?;
                    if encoded.len() > wire::transport::MAX_RESPONSE_BYTES {
                        return Err(denied());
                    }
                    Ok(encoded)
                });
                task.await.map_err(|_| denied())?
            })
            .await
            .map_err(|_| denied())?
    }
}
struct Busy(Arc<AtomicBool>);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Start once, before creating UHID. A lost privileged bus is fatal, never a
/// reason to fall back to PAM, a terminal, or another approval connection.
pub fn start(store_dir: std::path::PathBuf, tpm: ctap2::TpmCmdSender) -> Result<BusApproval> {
    let registry = Arc::new(Mutex::new(Registry::default()));
    let shared = registry.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result: Result<()> = (|| {
            crate::approval::runtime()?.block_on(async {
                let control = control();
                let (approval, signals, barriers) = control
                    .run(async {
                        let connection = wire::transport::connect_system_bus().await?;
                        // Subscribe before any registration, including startup races.
                        let rule = zbus::MatchRule::builder()
                            .msg_type(zbus::message::Type::Signal)
                            .build();
                        let signals =
                            MessageStream::for_match_rule(rule, &connection, Some(1024)).await?;
                        let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
                        let owner = proxy
                            .get_name_owner("org.freedesktop.login1".try_into()?)
                            .await
                            .ok()
                            .map(|owner| owner.as_str().to_owned());
                        shared.lock().unwrap().logind_owner = owner;
                        let (barrier, barriers) = tokio::sync::mpsc::channel(16);
                        let approval = BusApproval {
                            connection: connection.clone(),
                            registry: shared.clone(),
                            barrier,
                        };
                        connection
                            .object_server()
                            .at(
                                wire::DAEMON_PATH,
                                Daemon {
                                    approval: approval.clone(),
                                    store_dir,
                                    tpm,
                                    management_busy: Arc::new(AtomicBool::new(false)),
                                },
                            )
                            .await?;
                        connection.request_name(wire::BUS_NAME).await?;
                        Ok::<_, zbus::Error>((approval, signals, barriers))
                    })
                    .await
                    .map_err(|_| eyre!("system bus setup timed out"))??;
                tx.send(approval.clone())
                    .map_err(|_| eyre!("daemon startup abandoned"))?;
                monitor(signals, barriers, &approval).await;
                Err(eyre!("system bus monitor stopped"))
            })
        })();
        let mut state = shared.lock().unwrap();
        state.failed = true;
        state.invalidate();
        if let Err(error) = result {
            log::error!("privileged bus service failed: {error}");
        }
    });
    rx.recv_timeout(DEFAULT_APPROVAL_TIMEOUT + Duration::from_millis(200))
        .map_err(|_| eyre!("privileged bus service failed to start"))
}

async fn monitor(
    mut signals: MessageStream,
    mut barriers: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
    approval: &BusApproval,
) {
    loop {
        let message = tokio::select! {
            biased;
            message = std::future::poll_fn(|cx| std::pin::Pin::new(&mut signals).poll_next(cx)) => message,
            barrier = barriers.recv() => {
                let Some(barrier) = barrier else { break; };
                let _ = barrier.send(());
                continue;
            }
        };
        let Some(Ok(message)) = message else {
            break;
        };
        let header = message.header();
        let iface = header.interface().map(|v| v.as_str()).unwrap_or("");
        let member = header.member().map(|v| v.as_str()).unwrap_or("");
        if iface == "org.freedesktop.DBus"
            && member == "NameOwnerChanged"
            && header
                .sender()
                .is_some_and(|s| s.as_str() == "org.freedesktop.DBus")
        {
            let Ok((name, old, new)) = message.body().deserialize::<(String, String, String)>()
            else {
                approval.registry.lock().unwrap().invalidate();
                continue;
            };
            let mut registry = approval.registry.lock().unwrap();
            if name == "org.freedesktop.login1" {
                registry.logind_owner = (!new.is_empty()).then_some(new);
                registry.invalidate();
            } else if !old.is_empty() {
                registry.owner_lost(&name);
            }
        }
        // Object paths and interface strings alone do not authenticate signals.
        let from_logind = header.sender().is_some_and(|sender| {
            approval.registry.lock().unwrap().logind_owner.as_deref() == Some(sender.as_str())
        });
        if !from_logind {
            continue;
        }
        let logind_path = header
            .path()
            .is_some_and(|p| p.as_str().starts_with("/org/freedesktop/login1"));
        // Conservative invalidation: creation/removal of any session can change
        // sole-session eligibility. Ignore only unrelated property changes.
        if logind_path
            && (iface == "org.freedesktop.login1.Manager"
                || iface == "org.freedesktop.login1.Session")
        {
            approval.registry.lock().unwrap().invalidate();
        } else if logind_path
            && iface == "org.freedesktop.DBus.Properties"
            && member == "PropertiesChanged"
        {
            let changed = message
                .body()
                .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>();
            let sensitive = [
                "Active",
                "Remote",
                "LockedHint",
                "State",
                "Type",
                "Class",
                "Seat",
                "ActiveSession",
            ];
            if changed.as_ref().map_or(true, |(_, changed, invalidated)| {
                sensitive
                    .iter()
                    .any(|key| changed.contains_key(*key) || invalidated.iter().any(|v| v == key))
            }) {
                approval.registry.lock().unwrap().invalidate();
            }
        }
    }
    let mut registry = approval.registry.lock().unwrap();
    registry.failed = true;
    registry.invalidate();
}

#[cfg(test)]
#[path = "bus/tests.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn agent(sender: &str) -> Agent {
        Agent {
            sender: sender.into(),
            path: wire::AGENT_PATH.try_into().unwrap(),
            session: Session {
                id: "s1".into(),
                uid: 1000,
                seat: "seat0".into(),
                path: "/org/freedesktop/login1/session/s1".try_into().unwrap(),
            },
        }
    }
    #[test]
    fn registration_cannot_race_loss_or_replace_pending_agent() {
        let mut registry = Registry::default();
        registry.invalidate();
        assert!(!registry.register(0, agent(":1.1")));
        assert!(registry.register(1, agent(":1.1")));
        let (_, invalid) = registry.begin("request1".into()).unwrap();
        assert!(!registry.register(1, agent(":1.2")));
        assert!(registry.begin("request2".into()).is_none());
        registry.invalidate();
        assert!(invalid.load(Ordering::SeqCst));
        assert!(!registry.register(2, agent(":1.2")));
        registry.finish("stale");
        assert!(registry.pending.is_some());
        registry.finish("request1");
        assert!(registry.register(2, agent(":1.2")));
        assert!(invalid.load(Ordering::SeqCst)); // recovery cannot revive consent
    }
    #[test]
    fn disconnect_observed_before_registration_commit_invalidates_candidate() {
        let shared = Arc::new(Mutex::new(Registry::default()));
        shared.lock().unwrap().registering.insert(":1.1".into(), 1);
        let guard = Registration {
            registry: shared.clone(),
            sender: ":1.1".into(),
        };
        let generation = shared.lock().unwrap().generation;
        shared.lock().unwrap().owner_lost(":1.1");
        assert!(!shared.lock().unwrap().register(generation, agent(":1.1")));
        drop(guard);
        assert!(shared.lock().unwrap().registering.is_empty());
        let generation = shared.lock().unwrap().generation;
        assert!(shared.lock().unwrap().register(generation, agent(":1.2")));
        shared.lock().unwrap().owner_lost(":1.999");
        assert!(shared.lock().unwrap().agent.is_some());
    }

    #[test]
    fn live_registration_requires_explicit_unregistration() {
        let mut registry = Registry::default();
        assert!(registry.register(0, agent(":1.1")));
        assert!(registry.register(0, agent(":1.1")));
        assert!(!registry.register(0, agent(":1.2")));
        registry.failed = true;
        assert!(registry.begin("request".into()).is_none());
    }
}
