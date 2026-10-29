//! Consent state is independent of GTK and the bus. A dialog ticket can be
//! consumed only once and remains bound to its daemon-owner epoch until reply.
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use tpm_passkey_protocol::ApprovalContext;

pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SEEN_IDS: usize = 65_536;

pub enum Event {
    Show {
        token: u64,
        context: ApprovalContext,
        deadline: Instant,
    },
    Dismiss(u64),
}

struct Pending {
    token: u64,
    id: String,
    owner: String,
    deadline: Instant,
    decision: Option<bool>,
    reply: Option<oneshot::Sender<bool>>,
}

#[derive(Default)]
struct State {
    closed: bool,
    owner: Option<String>,
    history_owner: Option<String>,
    epoch: u64,
    next_token: u64,
    seen: HashSet<String>,
    pending: Option<Pending>,
}

#[derive(Clone)]
pub struct Shared {
    state: Arc<Mutex<State>>,
    events: async_channel::Sender<Event>,
    changed: watch::Sender<u64>,
}

impl Shared {
    pub fn new(events: async_channel::Sender<Event>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            events,
            changed: watch::channel(0).0,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn has_pending(&self) -> bool {
        self.state
            .lock()
            .expect("consent state lock")
            .pending
            .is_some()
    }

    pub fn owner(&self) -> (Option<String>, u64) {
        let state = self.state.lock().expect("consent state lock");
        (state.owner.clone(), state.epoch)
    }

    pub fn set_owner(&self, owner: Option<String>) {
        let mut state = self.state.lock().expect("consent state lock");
        if state.closed || state.owner == owner {
            return;
        }
        self.clear_pending(&mut state);
        // Preserve replay history through loss/reacquisition of the same
        // unique owner. A new daemon connection starts a fresh ID namespace.
        if owner.is_some() && state.history_owner != owner {
            state.seen.clear();
            state.history_owner = owner.clone();
        }
        state.owner = owner;
        state.epoch += 1;
        self.changed.send_replace(state.epoch);
    }

    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("consent state lock");
        state.closed = true;
        self.clear_pending(&mut state);
        state.owner = None;
        state.epoch += 1;
        self.changed.send_replace(state.epoch);
    }

    fn clear_pending(&self, state: &mut State) {
        if let Some(mut pending) = state.pending.take() {
            if let Some(reply) = pending.reply.take() {
                let _ = reply.send(false);
            }
            // Even if the UI channel is full, no stale window can grant consent:
            // the UI reconciles tickets on every event and has its own deadline.
            let _ = self.events.try_send(Event::Dismiss(pending.token));
        }
    }

    pub fn begin(
        &self,
        owner: &str,
        id: &str,
        context: ApprovalContext,
        deadline: Instant,
    ) -> Option<(u64, oneshot::Receiver<bool>)> {
        let now = Instant::now();
        if !valid_id(id) || !context.validate() || deadline <= now || deadline - now > MAX_TIMEOUT {
            return None;
        }
        let mut state = self.state.lock().expect("consent state lock");
        if state.closed
            || state.owner.as_deref() != Some(owner)
            || state.seen.len() >= MAX_SEEN_IDS
            || !state.seen.insert(id.to_owned())
        {
            return None;
        }
        // A request rejected while busy may not later become queued consent.
        if state.pending.is_some() {
            return None;
        }
        state.next_token += 1;
        let token = state.next_token;
        let (reply, receiver) = oneshot::channel();
        state.pending = Some(Pending {
            token,
            id: id.to_owned(),
            owner: owner.to_owned(),
            deadline,
            decision: None,
            reply: Some(reply),
        });
        if self
            .events
            .try_send(Event::Show {
                token,
                context,
                deadline,
            })
            .is_err()
        {
            self.clear_pending(&mut state);
            return None;
        }
        Some((token, receiver))
    }

    pub fn active(&self, token: u64) -> bool {
        let state = self.state.lock().expect("consent state lock");
        state.pending.as_ref().is_some_and(|p| {
            p.token == token && p.decision.is_none() && p.deadline > Instant::now()
        })
    }

    pub fn decide(&self, token: u64, allow: bool) {
        let mut state = self.state.lock().expect("consent state lock");
        if let Some(pending) = state
            .pending
            .as_mut()
            .filter(|p| p.token == token && p.decision.is_none())
        {
            let allow = allow && pending.deadline > Instant::now();
            pending.decision = Some(allow);
            if let Some(reply) = pending.reply.take() {
                let _ = reply.send(allow);
            }
            let _ = self.events.try_send(Event::Dismiss(token));
        }
    }

    pub fn cancel(&self, owner: &str, id: &str) {
        let mut state = self.state.lock().expect("consent state lock");
        if !valid_id(id) || state.owner.as_deref() != Some(owner) {
            return;
        }
        // Cancel may overtake Request's asynchronous sender authentication.
        // Tombstone its ID even before a ticket exists; it must never later
        // become a fresh dialog. Reaching the history limit fails begin closed.
        if state.seen.len() < MAX_SEEN_IDS {
            state.seen.insert(id.to_owned());
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|p| p.owner == owner && p.id == id)
        {
            self.clear_pending(&mut state);
        }
    }

    pub fn discard(&self, token: u64) {
        let mut state = self.state.lock().expect("consent state lock");
        if state.pending.as_ref().is_some_and(|p| p.token == token) {
            self.clear_pending(&mut state);
        }
    }

    pub fn complete(&self, token: u64, owner: &str, authenticated: bool) -> bool {
        let mut state = self.state.lock().expect("consent state lock");
        let allow = authenticated
            && state.owner.as_deref() == Some(owner)
            && state.pending.as_ref().is_some_and(|p| {
                p.token == token
                    && p.owner == owner
                    && p.decision == Some(true)
                    && p.deadline > Instant::now()
            });
        if state.pending.as_ref().is_some_and(|p| p.token == token) {
            self.clear_pending(&mut state);
        }
        allow
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Escape hidden directionality and control characters rather than truncating
/// the RP ID or letting untrusted text become markup or misleading UI controls.
pub fn plain_text(text: &str) -> String {
    let mut result = String::new();
    for ch in text.chars() {
        if ch.is_control()
            || (ch.is_whitespace() && ch != ' ')
            || unicode_general_category::get_general_category(ch)
                == unicode_general_category::GeneralCategory::Format
        {
            use std::fmt::Write;
            let _ = write!(result, "\\u{{{:x}}}", ch as u32);
        } else {
            result.push(ch);
        }
    }
    result
}

pub fn wording(context: &ApprovalContext) -> (&'static str, String) {
    match context.operation.as_str() {
        "register" => ("Create a passkey?", "Allow this website to create a TPM-backed passkey for the account shown below.".into()),
        "login" => ("Use a passkey?", format!("Confirm user presence to sign in. {} matching passkey(s); this does not select an account.", context.credential_count)),
        "selection" => ("Use this authenticator?", "Confirm user presence to select this authenticator. No account is selected by this approval.".into()),
        "reset" => ("Delete all passkeys?", "Resetting this authenticator deletes ALL stored passkeys and clears the FIDO PIN. This cannot be undone.".into()),
        _ => ("Invalid request", "Deny this request.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> ApprovalContext {
        ApprovalContext {
            operation: "login".into(),
            rp_id: "example.org".into(),
            rp_name: String::new(),
            account_name: String::new(),
            account_id: String::new(),
            credential_count: 3,
        }
    }
    fn setup() -> (Shared, async_channel::Receiver<Event>) {
        let (sender, receiver) = async_channel::bounded(16);
        let shared = Shared::new(sender);
        shared.set_owner(Some(":1.42".into()));
        (shared, receiver)
    }
    fn begin(shared: &Shared, id: &str) -> (u64, oneshot::Receiver<bool>) {
        shared
            .begin(
                ":1.42",
                id,
                context(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
    }
    #[test]
    fn exactly_one_pending_and_no_replay_or_queued_consent() {
        let (shared, _events) = setup();
        let (token, mut answer) = begin(&shared, "first");
        assert!(
            shared
                .begin(
                    ":1.42",
                    "second",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
        shared.decide(token, true);
        shared.decide(token, false);
        assert!(answer.try_recv().unwrap());
        assert!(shared.complete(token, ":1.42", true));
        for id in ["first", "second"] {
            assert!(
                shared
                    .begin(
                        ":1.42",
                        id,
                        context(),
                        Instant::now() + Duration::from_secs(5)
                    )
                    .is_none()
            );
        }
    }
    #[test]
    fn cancel_checks_owner_and_exact_id_and_invalidates_accepted_reply() {
        let (shared, _events) = setup();
        let (token, _answer) = begin(&shared, "first");
        shared.cancel(":1.99", "first");
        shared.cancel(":1.42", "wrong");
        assert!(shared.active(token));
        shared.decide(token, true);
        shared.cancel(":1.42", "first");
        assert!(!shared.complete(token, ":1.42", true));
        let (new_token, _) = begin(&shared, "new");
        shared.decide(token, true);
        assert!(shared.active(new_token));
    }
    #[test]
    fn cancellation_before_ticket_installation_prevents_late_dialog() {
        let (shared, _events) = setup();
        shared.cancel(":1.99", "unrelated");
        assert!(
            shared
                .begin(
                    ":1.42",
                    "unrelated",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_some()
        );
        shared.cancel(":1.42", "unrelated");
        shared.cancel(":1.42", "overtaken");
        assert!(
            shared
                .begin(
                    ":1.42",
                    "overtaken",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
        shared.set_owner(None);
        shared.set_owner(Some(":1.42".into()));
        assert!(
            shared
                .begin(
                    ":1.42",
                    "overtaken",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
    }

    #[test]
    fn owner_loss_and_restart_discard_even_previously_accepted_consent() {
        let (shared, _events) = setup();
        let (token, _) = begin(&shared, "first");
        shared.decide(token, true);
        shared.set_owner(None);
        shared.set_owner(Some(":1.42".into()));
        assert!(!shared.complete(token, ":1.42", true));
        assert!(
            shared
                .begin(
                    ":1.42",
                    "first",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
        let (token, mut answer) = begin(&shared, "fresh");
        shared.set_owner(Some(":1.43".into()));
        assert!(!answer.try_recv().unwrap());
        assert!(!shared.active(token));
    }
    #[test]
    fn malformed_context_ids_deadlines_and_wrong_callers_fail_closed() {
        let (shared, _events) = setup();
        for id in ["", "bad\n", "bad id"] {
            assert!(
                shared
                    .begin(
                        ":1.42",
                        id,
                        context(),
                        Instant::now() + Duration::from_secs(5)
                    )
                    .is_none()
            );
        }
        let mut invalid = context();
        invalid.rp_id.clear();
        assert!(
            shared
                .begin(
                    ":1.42",
                    "x",
                    invalid,
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
        assert!(
            shared
                .begin(":1.42", "x", context(), Instant::now())
                .is_none()
        );
        assert!(
            shared
                .begin(
                    ":1.42",
                    "x",
                    context(),
                    Instant::now() + Duration::from_secs(31)
                )
                .is_none()
        );
        assert!(
            shared
                .begin(
                    ":1.99",
                    "x",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
        let (token, _) = begin(&shared, "x");
        shared.decide(token, true);
        assert!(!shared.complete(token, ":1.42", false));
    }
    #[test]
    fn deadline_is_checked_again_at_click_and_final_reply() {
        let (shared, _events) = setup();
        let (token, mut answer) = begin(&shared, "expired-before-click");
        shared
            .state
            .lock()
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .deadline = Instant::now();
        shared.decide(token, true);
        assert!(!answer.try_recv().unwrap());
        assert!(!shared.complete(token, ":1.42", true));
        let (token, _) = begin(&shared, "expired-before-reply");
        shared.decide(token, true);
        shared
            .state
            .lock()
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .deadline = Instant::now();
        assert!(!shared.complete(token, ":1.42", true));
    }
    #[test]
    fn display_shutdown_permanently_rejects_future_consent() {
        let (shared, _events) = setup();
        let (token, mut answer) = begin(&shared, "pending");
        shared.shutdown();
        assert!(!answer.try_recv().unwrap());
        shared.set_owner(Some(":1.42".into()));
        assert!(!shared.complete(token, ":1.42", true));
        assert!(
            shared
                .begin(
                    ":1.42",
                    "fresh",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
    }
    #[test]
    fn closed_ui_channel_cannot_grant_consent() {
        let (sender, receiver) = async_channel::bounded(1);
        drop(receiver);
        let shared = Shared::new(sender);
        shared.set_owner(Some(":1.42".into()));
        assert!(
            shared
                .begin(
                    ":1.42",
                    "x",
                    context(),
                    Instant::now() + Duration::from_secs(5)
                )
                .is_none()
        );
    }
    #[test]
    fn untrusted_text_is_plain_full_length_and_direction_safe() {
        let text = "<b>example.org</b>\u{202e}\n";
        assert_eq!(plain_text(text), "<b>example.org</b>\\u{202e}\\u{a}");
        assert_eq!(
            plain_text("ex\u{200b}ample\u{feff}.org\u{2028}"),
            "ex\\u{200b}ample\\u{feff}.org\\u{2028}"
        );
        let long = "x".repeat(2048);
        assert_eq!(plain_text(&long), long);
        let mut ctx = context();
        ctx.operation = "reset".into();
        let (_, warning) = wording(&ctx);
        assert!(warning.contains("ALL stored passkeys") && warning.contains("clears the FIDO PIN"));
        ctx.operation = "login".into();
        assert!(wording(&ctx).1.contains("3 matching"));
        assert!(wording(&ctx).1.contains("does not select an account"));
    }
}
