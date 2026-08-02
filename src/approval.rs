use std::io::{self, Write};

use crate::session;

/// Boundary used by the authenticator to request transaction-specific consent.
pub trait UserApproval: Send {
    fn approve(&self, prompt: &str, session: &session::SessionContext) -> bool;
}

/// Production approval provider backed by polkit with a terminal fallback.
#[derive(Debug, Default)]
pub struct SystemApproval;

impl UserApproval for SystemApproval {
    fn approve(&self, prompt: &str, session: &session::SessionContext) -> bool {
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

        is_affirmative(&answer)
    }
}

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
}

#[cfg(test)]
mod tests {
    use super::is_affirmative;

    #[test]
    fn only_explicit_affirmative_answers_are_accepted() {
        for answer in ["y", "Y", "yes", "Yes", "YES", " yes\n"] {
            assert!(is_affirmative(answer));
        }
        for answer in ["", "n", "no", "true", "sure"] {
            assert!(!is_affirmative(answer));
        }
    }
}
