//! Real private-bus tests (no system daemon, display, TPM, or polkit installation).
use super::*;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::atomic::AtomicUsize,
};
use zbus::zvariant::OwnedValue;

struct PrivateBus {
    child: Child,
    address: String,
    config: std::path::PathBuf,
}
impl PrivateBus {
    fn new() -> Self {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let config = std::env::temp_dir().join(format!("tpm-passkey-bus-{}.conf", hex::encode(id)));
        std::fs::write(&config, r#"<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>"#).unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg("--config-file")
            .arg(&config)
            .args(["--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon in PATH");
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().into(),
            config,
        }
    }
    async fn connect(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

#[derive(Clone)]
struct Authority {
    allow: Arc<AtomicBool>,
    stall: Arc<AtomicBool>,
    checks: Arc<AtomicUsize>,
    cancels: Arc<AtomicUsize>,
    subjects: Arc<Mutex<Vec<String>>>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            allow: Arc::new(AtomicBool::new(true)),
            stall: Arc::new(AtomicBool::new(false)),
            checks: Arc::default(),
            cancels: Arc::default(),
            subjects: Arc::default(),
        }
    }
}
#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        _action: String,
        _details: HashMap<String, String>,
        _flags: u32,
        _id: String,
    ) -> ((bool, bool, HashMap<String, String>),) {
        assert_eq!(subject.0, "system-bus-name");
        self.subjects.lock().unwrap().push(
            <&str>::try_from(subject.1.get("name").unwrap())
                .unwrap()
                .into(),
        );
        self.checks.fetch_add(1, Ordering::SeqCst);
        if self.stall.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        // Polkit returns ONE authorization-result structure, not three args.
        ((self.allow.load(Ordering::SeqCst), false, HashMap::new()),)
    }
    fn cancel_check_authorization(&self, _id: String) {
        self.cancels.fetch_add(1, Ordering::SeqCst);
    }
}
async fn authority(bus: &PrivateBus, authority: Authority) -> Connection {
    let connection = bus.connect().await;
    connection
        .object_server()
        .at("/org/freedesktop/PolicyKit1/Authority", authority)
        .await
        .unwrap();
    connection
        .request_name("org.freedesktop.PolicyKit1")
        .await
        .unwrap();
    connection
}
fn short_control(ms: u64) -> ApprovalControl {
    ApprovalControl::new(None, Instant::now() + Duration::from_millis(ms))
}

#[derive(Clone)]
struct Login {
    locked: Arc<AtomicBool>,
    multiple: Arc<AtomicBool>,
    uid: u32,
}
#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Login {
    fn list_sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
        let mut result = vec![(
            "s1".into(),
            self.uid,
            "user".into(),
            "seat0".into(),
            "/org/freedesktop/login1/session/s1".try_into().unwrap(),
        )];
        if self.multiple.load(Ordering::SeqCst) {
            result.push((
                "s2".into(),
                self.uid,
                "user".into(),
                "seat1".into(),
                "/org/freedesktop/login1/session/s2".try_into().unwrap(),
            ));
        }
        result
    }
}
#[derive(Clone)]
struct DesktopSession {
    locked: Arc<AtomicBool>,
    active: bool,
}
#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl DesktopSession {
    #[zbus(property)]
    fn active(&self) -> bool {
        self.active
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn r#type(&self) -> &str {
        "wayland"
    }
    #[zbus(property)]
    fn class(&self) -> &str {
        "user"
    }
    #[zbus(property)]
    fn state(&self) -> &str {
        "active"
    }
}
async fn login(bus: &PrivateBus) -> (Connection, Login) {
    let state = Login {
        locked: Arc::new(AtomicBool::new(false)),
        multiple: Arc::default(),
        uid: unsafe { libc::geteuid() },
    };
    let connection = bus.connect().await;
    connection
        .object_server()
        .at("/org/freedesktop/login1", state.clone())
        .await
        .unwrap();
    for path in [
        "/org/freedesktop/login1/session/s1",
        "/org/freedesktop/login1/session/s2",
    ] {
        connection
            .object_server()
            .at(
                path,
                DesktopSession {
                    locked: state.locked.clone(),
                    // A second inactive session is still ambiguous for a per-user
                    // agent whose service PID has no graphical session scope.
                    active: path.ends_with("s1"),
                },
            )
            .await
            .unwrap();
    }
    connection
        .request_name("org.freedesktop.login1")
        .await
        .unwrap();
    (connection, state)
}
#[derive(Clone, Default)]
struct GtkAgent {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    stall_cancel: Arc<AtomicBool>,
    cancelled: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<Vec<(String, ApprovalContext)>>>,
}
#[zbus::interface(name = "io.github.pineapplehunter.TpmPasskey1.ApprovalAgent")]
impl GtkAgent {
    async fn request(&self, id: String, context: ApprovalContext, _timeout_ms: u32) -> bool {
        self.requests.lock().unwrap().push((id, context));
        self.entered.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        true
    }
    async fn cancel(&self, id: String) {
        self.cancelled.lock().unwrap().push(id);
        if self.stall_cancel.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}
async fn install(bus: &PrivateBus) -> (BusApproval, tokio::task::JoinHandle<()>) {
    let connection = bus.connect().await;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .build();
    let signals = MessageStream::for_match_rule(rule, &connection, Some(1024))
        .await
        .unwrap();
    let (barrier, barriers) = tokio::sync::mpsc::channel(16);
    let approval = BusApproval {
        connection: connection.clone(),
        registry: Arc::new(Mutex::new(Registry::default())),
        barrier,
    };
    let (tpm, _rx) = std::sync::mpsc::channel();
    connection
        .object_server()
        .at(
            wire::DAEMON_PATH,
            Daemon {
                approval: approval.clone(),
                store_dir: "/does-not-exist".into(),
                tpm,
                management_busy: Arc::new(AtomicBool::new(false)),
            },
        )
        .await
        .unwrap();
    connection.request_name(wire::BUS_NAME).await.unwrap();
    let monitored = approval.clone();
    let task = tokio::spawn(async move {
        monitor(signals, barriers, &monitored).await;
    });
    (approval, task)
}
async fn register(connection: &Connection) -> zbus::Result<zbus::Message> {
    let path: OwnedObjectPath = wire::AGENT_PATH.try_into().unwrap();
    connection
        .call_method(
            Some(wire::BUS_NAME),
            wire::DAEMON_PATH,
            Some(wire::DAEMON_IFACE),
            "RegisterAgent",
            &(path,),
        )
        .await
}
async fn entered(agent: &GtkAgent) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !agent.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("agent entered");
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn actual_caller_polkit_denial_disappearance_and_deadline() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let policy = Authority::default();
        let _authority = authority(&bus, policy.clone()).await;
        let daemon = bus.connect().await;
        let caller = bus.connect().await;
        let name = caller.unique_name().unwrap().as_str().to_owned();
        assert_eq!(
            crate::polkit::authorize(
                &daemon,
                &name,
                wire::ACTION_READ,
                false,
                &short_control(1000)
            )
            .await,
            Ok(true)
        );
        assert_eq!(*policy.subjects.lock().unwrap(), vec![name.clone()]);
        policy.allow.store(false, Ordering::SeqCst);
        assert_eq!(
            crate::polkit::authorize(
                &daemon,
                &name,
                wire::ACTION_READ,
                false,
                &short_control(1000)
            )
            .await,
            Ok(false)
        );
        assert_eq!(
            crate::polkit::authorize(
                &daemon,
                wire::BUS_NAME,
                wire::ACTION_READ,
                false,
                &short_control(1000)
            )
            .await,
            Ok(false)
        );
        policy.stall.store(true, Ordering::SeqCst);
        let start = Instant::now();
        assert_eq!(
            crate::polkit::authorize(&daemon, &name, wire::ACTION_READ, true, &short_control(60))
                .await,
            Err(ApprovalOutcome::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_millis(250));
        let vanish = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            caller.close().await.unwrap();
        };
        let control = short_control(1000);
        let check = crate::polkit::authorize(&daemon, &name, wire::ACTION_READ, true, &control);
        let (result, ()) = tokio::join!(check, vanish);
        assert_eq!(result, Ok(false));
        assert!(policy.cancels.load(Ordering::SeqCst) >= 3);
    });
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn management_authorizes_before_fd_decode_and_rejects_operation_substitution() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let policy = Authority::default();
        policy.allow.store(false, Ordering::SeqCst);
        let _authority = authority(&bus, policy.clone()).await;
        let daemon = bus.connect().await;
        let registry = Arc::new(Mutex::new(Registry::default()));
        let (barrier, _barriers) = tokio::sync::mpsc::channel(16);
        let approval = BusApproval {
            connection: daemon.clone(),
            registry,
            barrier,
        };
        let (tpm, _rx) = std::sync::mpsc::channel();
        daemon
            .object_server()
            .at(
                wire::DAEMON_PATH,
                Daemon {
                    approval,
                    store_dir: "/does-not-exist".into(),
                    tpm,
                    management_busy: Arc::new(AtomicBool::new(false)),
                },
            )
            .await
            .unwrap();
        daemon.request_name(wire::BUS_NAME).await.unwrap();
        let caller = bus.connect().await;
        // If descriptor decoding happened before authorization, this invalid
        // FD would fail without ever calling our authority (count must be 1).
        let request = OwnedFd::from(std::os::fd::OwnedFd::from(
            std::fs::File::open("/dev/null").unwrap(),
        ));
        let result = caller
            .call_method(
                Some(wire::BUS_NAME),
                wire::DAEMON_PATH,
                Some(wire::DAEMON_IFACE),
                "Manage",
                &("show-config", request),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(policy.checks.load(Ordering::SeqCst), 1);
        assert_eq!(
            policy.subjects.lock().unwrap()[0],
            caller.unique_name().unwrap().as_str()
        );
        policy.allow.store(true, Ordering::SeqCst);
        let request = wire::transport::seal_request(&wire::ManagementRequest::ShowConfig).unwrap();
        let result = caller
            .call_method(
                Some(wire::BUS_NAME),
                wire::DAEMON_PATH,
                Some(wire::DAEMON_IFACE),
                "Manage",
                &("disable-default-pcr-policy", request),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(policy.checks.load(Ordering::SeqCst), 2);
        let invalid = OwnedFd::from(std::os::fd::OwnedFd::from(
            std::fs::File::open("/dev/null").unwrap(),
        ));
        assert!(
            caller
                .call_method(
                    Some(wire::BUS_NAME),
                    wire::DAEMON_PATH,
                    Some(wire::DAEMON_IFACE),
                    "Manage",
                    &("show-config", invalid)
                )
                .await
                .is_err()
        );
        assert_eq!(policy.checks.load(Ordering::SeqCst), 3);
    });
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn registration_is_independent_of_logind_and_disconnects() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let _authority = authority(&bus, Authority::default()).await;
        let (approval, monitor) = install(&bus).await;
        let caller = bus.connect().await;
        assert!(register(&caller).await.is_ok());
        assert!(approval.registry.lock().unwrap().agent.is_some());
        caller.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while approval.registry.lock().unwrap().agent.is_some() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        monitor.abort();
    });
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn unrelated_lock_signals_do_not_cancel_pending_consent() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let _authority = authority(&bus, Authority::default()).await;
        let (logind, _session) = login(&bus).await;
        let (approval, monitor) = install(&bus).await;
        let caller = bus.connect().await;
        let agent = GtkAgent::default();
        caller
            .object_server()
            .at(wire::AGENT_PATH, agent.clone())
            .await
            .unwrap();
        register(&caller).await.unwrap();
        let pending = approval.clone();
        let task = tokio::task::spawn_blocking(move || {
            pending.approve_context_controlled(
                &crate::approval::context("login", "full.example.test"),
                &short_control(1000),
            )
        });
        entered(&agent).await;
        // A second registration must not be queued as a replacement while the
        // active transaction owns the registry, even from the same sender.
        assert!(register(&caller).await.is_err());
        for locked in [true, false] {
            let mut changed = HashMap::new();
            changed.insert("LockedHint", zbus::zvariant::Value::from(locked));
            logind
                .emit_signal(
                    None::<&str>,
                    "/org/freedesktop/login1/session/s1",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &(
                        "org.freedesktop.login1.Session",
                        changed,
                        Vec::<String>::new(),
                    ),
                )
                .await
                .unwrap();
        }
        agent.release.store(true, Ordering::SeqCst);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            ApprovalOutcome::Approved
        );
        assert!(approval.registry.lock().unwrap().agent.is_some());
        assert!(agent.cancelled.lock().unwrap().is_empty());
        assert_eq!(
            agent.requests.lock().unwrap()[0].1.rp_id,
            "full.example.test"
        );
        monitor.abort();
    });
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn agent_wait_cancel_and_deadline_share_one_budget_and_cancel_exact_request() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let _authority = authority(&bus, Authority::default()).await;
        let (_logind, _session) = login(&bus).await;
        let (approval, monitor) = install(&bus).await;
        let caller = bus.connect().await;
        let agent = GtkAgent::default();
        caller
            .object_server()
            .at(wire::AGENT_PATH, agent.clone())
            .await
            .unwrap();
        register(&caller).await.unwrap();
        let pending = approval.clone();
        agent.stall_cancel.store(true, Ordering::SeqCst);
        let start = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            pending.approve_context_controlled(
                &crate::approval::context("reset", ""),
                &short_control(80),
            )
        })
        .await
        .unwrap();
        assert_eq!(result, ApprovalOutcome::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(250));
        assert_eq!(
            agent.cancelled.lock().unwrap()[0],
            agent.requests.lock().unwrap()[0].0
        );
        agent.entered.store(false, Ordering::SeqCst);
        let cancel = Arc::new(AtomicBool::new(false));
        let control = ApprovalControl::new(
            Some(cancel.clone()),
            Instant::now() + Duration::from_secs(1),
        );
        let pending = approval.clone();
        let task = tokio::task::spawn_blocking(move || {
            pending.approve_context_controlled(&crate::approval::context("selection", ""), &control)
        });
        entered(&agent).await;
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(task.await.unwrap(), ApprovalOutcome::Cancelled);
        let requests = agent.requests.lock().unwrap();
        assert_ne!(requests[0].0, requests[1].0);
        assert_eq!(agent.cancelled.lock().unwrap()[1], requests[1].0);
        drop(requests);
        agent.entered.store(false, Ordering::SeqCst);
        let pending = approval.clone();
        let task = tokio::task::spawn_blocking(move || {
            pending.approve_context_controlled(
                &crate::approval::context("selection", ""),
                &short_control(1000),
            )
        });
        entered(&agent).await;
        let start = Instant::now();
        caller.close().await.unwrap();
        assert_eq!(task.await.unwrap(), ApprovalOutcome::Denied);
        assert!(start.elapsed() < Duration::from_millis(250));
        monitor.abort();
    });
}

#[test]
#[ignore = "requires dbus-daemon in PATH; run with --ignored"]
fn session_changes_do_not_revoke_agent() {
    crate::approval::runtime().unwrap().block_on(async {
        let bus = PrivateBus::new();
        let _authority = authority(&bus, Authority::default()).await;
        let (_logind, session) = login(&bus).await;
        let (approval, monitor) = install(&bus).await;
        let caller = bus.connect().await;
        let agent = GtkAgent::default();
        caller
            .object_server()
            .at(wire::AGENT_PATH, agent.clone())
            .await
            .unwrap();
        register(&caller).await.unwrap();
        let pending = approval.clone();
        let task = tokio::task::spawn_blocking(move || {
            pending.approve_context_controlled(
                &crate::approval::context("selection", ""),
                &short_control(1000),
            )
        });
        entered(&agent).await;
        session.multiple.store(true, Ordering::SeqCst);
        agent.release.store(true, Ordering::SeqCst);
        assert_eq!(task.await.unwrap(), ApprovalOutcome::Approved);
        assert!(approval.registry.lock().unwrap().agent.is_some());
        session.multiple.store(false, Ordering::SeqCst);
        let pending = approval.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || pending.approve_context_controlled(
                &crate::approval::context("selection", ""),
                &short_control(1000)
            ))
            .await
            .unwrap(),
            ApprovalOutcome::Approved
        );
        register(&caller).await.unwrap();
        let pending = approval.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || pending.approve_context_controlled(
                &crate::approval::context("selection", ""),
                &short_control(1000)
            ))
            .await
            .unwrap(),
            ApprovalOutcome::Approved
        );
        monitor.abort();
    });
}
