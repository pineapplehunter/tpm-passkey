use std::{
    future::Future,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Boundary for transaction-specific user presence (UP), never built-in UV.
pub trait UserApproval: Send {
    fn approve(&self, prompt: &str) -> bool;

    /// Compatibility adapter for existing providers. Only providers overriding
    /// this method (including SystemApproval) can interrupt a pending approval.
    fn approve_controlled(&self, prompt: &str, control: &ApprovalControl) -> ApprovalOutcome {
        if let Some(outcome) = control.stopped() {
            return outcome;
        }
        let approved = self.approve(prompt);
        control.stopped().unwrap_or(if approved {
            ApprovalOutcome::Approved
        } else {
            ApprovalOutcome::Denied
        })
    }
}

#[derive(Clone, Debug)]
pub struct ApprovalControl {
    pub cancel: Option<Arc<AtomicBool>>,
    pub deadline: Instant,
}

impl ApprovalControl {
    pub fn new(cancel: Option<Arc<AtomicBool>>, deadline: Instant) -> Self {
        Self { cancel, deadline }
    }

    pub(crate) fn stopped(&self) -> Option<ApprovalOutcome> {
        if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            Some(ApprovalOutcome::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(ApprovalOutcome::TimedOut)
        } else {
            None
        }
    }

    /// All async stages use the same absolute deadline. Dropping the pending
    /// future interrupts bus setup, logind discovery, polkit, or terminal I/O.
    pub(crate) async fn run<F: Future>(&self, work: F) -> Result<F::Output, ApprovalOutcome> {
        tokio::pin!(work);
        loop {
            if let Some(outcome) = self.stopped() {
                return Err(outcome);
            }
            let wake = self.deadline.min(Instant::now() + CANCEL_POLL_INTERVAL);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(wake.into()) => {}
                result = &mut work => return self.stopped().map_or(Ok(result), Err),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
    Cancelled,
    TimedOut,
}

/// Production approval provider backed by polkit with a terminal fallback.
#[derive(Debug, Default)]
pub struct SystemApproval;

impl UserApproval for SystemApproval {
    fn approve(&self, prompt: &str) -> bool {
        self.approve_controlled(
            prompt,
            &ApprovalControl::new(None, Instant::now() + DEFAULT_APPROVAL_TIMEOUT),
        ) == ApprovalOutcome::Approved
    }

    fn approve_controlled(&self, prompt: &str, control: &ApprovalControl) -> ApprovalOutcome {
        if let Some(outcome) = control.stopped() {
            return outcome;
        }
        let Ok(runtime) = runtime() else {
            return ApprovalOutcome::Denied;
        };
        runtime.block_on(async {
            match crate::polkit::check_active_session_controlled(control).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    log::warn!("polkit unavailable, falling back: {error:?}");
                    control
                        .run(terminal_approval(prompt))
                        .await
                        .unwrap_or_else(|outcome| outcome)
                }
            }
        })
    }
}

pub(crate) fn runtime() -> io::Result<tokio::runtime::Runtime> {
    // zbus uses the tokio backend: no blocking transport or detached worker.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

async fn terminal_approval(prompt: &str) -> ApprovalOutcome {
    if !io::stdin().is_terminal() {
        return ApprovalOutcome::Denied;
    }
    // Reopen, rather than dup, so O_NONBLOCK does not change stdin's flags.
    // Write the prompt to this terminal too: stdout could be a full pipe.
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open("/proc/self/fd/0");
    match terminal {
        Ok(terminal) => terminal_approval_on(terminal, prompt).await,
        Err(_) => ApprovalOutcome::Denied,
    }
}

async fn terminal_approval_on(terminal: std::fs::File, prompt: &str) -> ApprovalOutcome {
    if !terminal.is_terminal() {
        return ApprovalOutcome::Denied;
    }
    match terminal_answer(terminal, prompt).await {
        Ok(true) => ApprovalOutcome::Approved,
        Ok(false) | Err(_) => ApprovalOutcome::Denied,
    }
}

async fn terminal_answer(terminal: std::fs::File, prompt: &str) -> io::Result<bool> {
    use tokio::io::{Interest, unix::AsyncFd};

    let terminal = AsyncFd::new(terminal)?;
    let prompt = format!("{prompt}? [y/N] ");
    let mut remaining = prompt.as_bytes();
    while !remaining.is_empty() {
        let written = terminal
            .async_io(Interest::WRITABLE, |mut file| file.write(remaining))
            .await?;
        if written == 0 {
            return Ok(false);
        }
        remaining = &remaining[written..];
    }

    let mut answer = Vec::new();
    loop {
        let mut byte = [0u8];
        let read = terminal
            .async_io(Interest::READABLE, |mut file| file.read(&mut byte))
            .await?;
        if read == 0 {
            return Ok(false);
        }
        if byte[0] == b'\n' {
            return Ok(is_affirmative(std::str::from_utf8(&answer).unwrap_or("")));
        }
        if answer.len() >= 64 {
            return Ok(false);
        }
        answer.push(byte[0]);
    }
}

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, future::pending, os::fd::FromRawFd};

    #[test]
    fn only_explicit_affirmative_answers_are_accepted() {
        for answer in ["y", "Y", "yes", "Yes", "YES", " yes\n"] {
            assert!(is_affirmative(answer));
        }
        for answer in ["", "n", "no", "true", "sure"] {
            assert!(!is_affirmative(answer));
        }
    }

    struct Dropped<'a>(&'a Cell<bool>);
    impl Drop for Dropped<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn pending_shared_workflow_is_cancelled_and_dropped() {
        runtime().unwrap().block_on(async {
            let flag = Arc::new(AtomicBool::new(false));
            let control =
                ApprovalControl::new(Some(flag.clone()), Instant::now() + Duration::from_secs(2));
            let entered = Cell::new(false);
            let dropped = Cell::new(false);
            // The same scope used around connection + logind + polkit. Simulate
            // a completed bus setup followed by a lookup that never replies.
            let workflow = async {
                tokio::task::yield_now().await;
                let _guard = Dropped(&dropped);
                entered.set(true);
                pending::<()>().await;
            };
            let cancel = async {
                while !entered.get() {
                    tokio::task::yield_now().await;
                }
                flag.store(true, Ordering::Relaxed);
                Instant::now()
            };
            let (result, cancelled_at) = tokio::join!(control.run(workflow), cancel);
            assert_eq!(result, Err(ApprovalOutcome::Cancelled));
            assert!(dropped.get());
            assert!(cancelled_at.elapsed() < Duration::from_millis(200));
        });
    }

    #[test]
    fn pending_shared_workflow_hits_original_deadline() {
        runtime().unwrap().block_on(async {
            let control = ApprovalControl::new(None, Instant::now() + Duration::from_millis(80));
            let entered = Cell::new(false);
            let dropped = Cell::new(false);
            let result = control
                .run(async {
                    // Earlier work consumes part of the ONE action budget.
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let _guard = Dropped(&dropped);
                    entered.set(true);
                    pending::<()>().await;
                })
                .await;
            assert_eq!(result, Err(ApprovalOutcome::TimedOut));
            assert!(entered.get() && dropped.get());
            assert!(Instant::now().duration_since(control.deadline) < Duration::from_millis(200));
        });
    }

    fn terminal_pair() -> (std::fs::File, std::fs::File) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: valid output pointers; null requests default terminal settings.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: successful openpty gives us ownership of these descriptors.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        use std::os::fd::AsRawFd;
        let fd = slave.as_raw_fd();
        // SAFETY: valid terminal fd and initialized termios after tcgetattr.
        unsafe {
            let mut settings = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut settings), 0);
            libc::cfmakeraw(&mut settings);
            assert_eq!(libc::tcsetattr(fd, libc::TCSANOW, &settings), 0);
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK), 0);
        }
        (master, slave)
    }

    #[test]
    fn partial_terminal_input_can_be_cancelled() {
        let (mut master, slave) = terminal_pair();
        master.write_all(b"y").unwrap(); // readable but no complete answer
        runtime().unwrap().block_on(async {
            let flag = Arc::new(AtomicBool::new(false));
            let control =
                ApprovalControl::new(Some(flag.clone()), Instant::now() + Duration::from_secs(2));
            let cancel = async {
                tokio::time::sleep(Duration::from_millis(40)).await;
                flag.store(true, Ordering::Relaxed);
            };
            let (result, ()) =
                tokio::join!(control.run(terminal_approval_on(slave, "approve")), cancel);
            assert_eq!(result, Err(ApprovalOutcome::Cancelled));
        });
    }

    #[test]
    fn pending_terminal_input_times_out() {
        let (_master, slave) = terminal_pair();
        let control = ApprovalControl::new(None, Instant::now() + Duration::from_millis(40));
        let result = runtime()
            .unwrap()
            .block_on(control.run(terminal_approval_on(slave, "approve")));
        assert_eq!(result, Err(ApprovalOutcome::TimedOut));
    }

    #[test]
    fn terminal_requires_complete_explicit_answer() {
        let (mut master, slave) = terminal_pair();
        master.write_all(b"yes\n").unwrap();
        let control = ApprovalControl::new(None, Instant::now() + Duration::from_secs(1));
        let result = runtime()
            .unwrap()
            .block_on(control.run(terminal_approval_on(slave, "approve")));
        assert_eq!(result, Ok(ApprovalOutcome::Approved));
    }

    #[test]
    fn nonterminal_input_fails_closed() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let result = runtime()
            .unwrap()
            .block_on(terminal_approval_on(file, "approve"));
        assert_eq!(result, ApprovalOutcome::Denied);
    }

    #[test]
    fn legacy_provider_remains_source_compatible() {
        struct Legacy;
        impl UserApproval for Legacy {
            fn approve(&self, _: &str) -> bool {
                true
            }
        }
        let control = ApprovalControl::new(None, Instant::now() + DEFAULT_APPROVAL_TIMEOUT);
        assert_eq!(
            Legacy.approve_controlled("approve", &control),
            ApprovalOutcome::Approved
        );
        let flag = Arc::new(AtomicBool::new(true));
        let stopped = ApprovalControl::new(Some(flag), control.deadline);
        assert_eq!(
            SystemApproval.approve_controlled("approve", &stopped),
            ApprovalOutcome::Cancelled
        );
    }
}
