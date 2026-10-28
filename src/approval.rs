use std::io::{self, Write};

/// Boundary used by the authenticator to request transaction-specific consent.
pub trait UserApproval: Send {
    fn approve(&self, prompt: &str) -> bool;
}

/// Production approval provider backed by polkit with a terminal fallback.
#[derive(Debug, Default)]
pub struct SystemApproval;

impl UserApproval for SystemApproval {
    fn approve(&self, prompt: &str) -> bool {
        match crate::polkit::check_active_session() {
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

        let mut stdout = io::stdout();
        if write!(stdout, "{prompt}? [y/N] ")
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
