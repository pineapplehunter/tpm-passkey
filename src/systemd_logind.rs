use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};

/// A registration is tied to exactly one local, unlocked graphical session,
/// not to the service process's cgroup or its logind session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Session {
    pub id: String,
    pub uid: u32,
    pub seat: String,
    pub path: OwnedObjectPath,
}

pub(crate) async fn eligible_session(connection: &Connection) -> zbus::Result<Option<Session>> {
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "ListSessions",
            &(),
        )
        .await?
        .body()
        .deserialize()?;
    let mut eligible = None;
    let mut graphical_sessions = 0;
    for (id, uid, _, seat, path) in sessions {
        if seat.is_empty() {
            continue;
        }
        let properties: std::collections::HashMap<String, OwnedValue> = connection
            .call_method(
                Some("org.freedesktop.login1"),
                path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "GetAll",
                &("org.freedesktop.login1.Session",),
            )
            .await?
            .body()
            .deserialize()?;
        let boolean = |name: &str| properties.get(name).and_then(|v| bool::try_from(v).ok());
        let text = |name: &str| properties.get(name).and_then(|v| <&str>::try_from(v).ok());
        // A per-user service need not belong to a graphical session scope.
        // With two graphical sessions (even one inactive/locked), UID alone
        // cannot identify which display its connection represents. Reject that
        // ambiguity rather than routing consent to an old session's agent.
        if boolean("Remote") == Some(false)
            && matches!(text("Type"), Some("x11" | "wayland"))
            && text("Class") == Some("user")
        {
            graphical_sessions += 1;
            if graphical_sessions > 1 {
                return Ok(None);
            }
        }
        if !session_eligible(
            boolean("Active"),
            boolean("Remote"),
            boolean("LockedHint"),
            text("Type"),
            text("Class"),
            text("State"),
        ) {
            continue;
        }
        if eligible.is_some() {
            return Ok(None);
        }
        eligible = Some(Session {
            id,
            uid,
            seat,
            path,
        });
    }
    Ok(eligible)
}

fn session_eligible(
    active: Option<bool>,
    remote: Option<bool>,
    locked: Option<bool>,
    kind: Option<&str>,
    class: Option<&str>,
    state: Option<&str>,
) -> bool {
    active == Some(true)
        && remote == Some(false)
        && locked == Some(false)
        && matches!(kind, Some("x11" | "wayland"))
        && class == Some("user")
        && state == Some("active")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_known_active_unlocked_local_graphical_users_are_eligible() {
        assert!(session_eligible(
            Some(true),
            Some(false),
            Some(false),
            Some("wayland"),
            Some("user"),
            Some("active")
        ));
        for (active, remote, locked, kind, class, state) in [
            (
                None,
                Some(false),
                Some(false),
                Some("wayland"),
                Some("user"),
                Some("active"),
            ),
            (
                Some(true),
                Some(true),
                Some(false),
                Some("wayland"),
                Some("user"),
                Some("active"),
            ),
            (
                Some(true),
                Some(false),
                Some(true),
                Some("wayland"),
                Some("user"),
                Some("active"),
            ),
            (
                Some(true),
                Some(false),
                Some(false),
                Some("tty"),
                Some("user"),
                Some("active"),
            ),
            (
                Some(true),
                Some(false),
                Some(false),
                Some("wayland"),
                Some("greeter"),
                Some("active"),
            ),
            (
                Some(true),
                Some(false),
                Some(false),
                Some("wayland"),
                Some("user"),
                Some("closing"),
            ),
        ] {
            assert!(!session_eligible(
                active, remote, locked, kind, class, state
            ));
        }
    }
}
