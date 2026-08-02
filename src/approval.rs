use std::io::{self, Write};

use crate::session;

pub fn approve(prompt: &str, session: &session::SessionContext) -> bool {
    if cfg!(test) {
        let _ = session;
        log::warn!("auto-approving in test: {prompt}");
        return true;
    }

    // A system daemon has no useful process subject: its process is root.
    // Use the logged-in session leader so polkit can contact that user's agent.
    if let (Some(session_id), Some(leader_pid), Some(user_uid)) =
        (&session.session_id, session.leader_pid, session.uid)
    {
        match crate::polkit::check_session(session_id, leader_pid, user_uid) {
            Ok(true) => {
                log::info!("polkit authorized approval: {prompt}");
                return true;
            }
            Ok(false) => {
                log::warn!("polkit denied approval: {prompt}");
                return false;
            }
            Err(error) => {
                log::warn!("polkit unavailable, falling back: {error:?}");
            }
        }
    } else {
        log::warn!("no login session available for polkit approval");
    }

    let mut stdout = io::stdout();
    if write!(
        stdout,
        "[{session}] {prompt}? [y/N] ",
        session = session.describe()
    )
    .and_then(|_| stdout.flush())
    .is_err()
    {
        return false;
    }

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
}

#[cfg(test)]
mod tests {
    use super::approve;
    use crate::session::{DaemonSessionModel, SessionContext};

    #[test]
    fn auto_approve_returns_true() {
        let session = SessionContext {
            model: DaemonSessionModel::ActiveGraphicalSession,
            user: Some("alice".to_owned()),
            uid: Some(1000),
            session_id: None,
            leader_pid: None,
            seat: Some("seat0".to_owned()),
            display: Some(":0".to_owned()),
            wayland_display: None,
            dbus_session_bus_address: None,
        };
        assert!(approve("Approve passkey request", &session));
    }
}
