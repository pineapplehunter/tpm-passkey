use zbus::{
    blocking::Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};

/// Find a process subject for routing polkit prompts to the desktop agent.
/// This does not identify the sender of a HID request or authorize credentials.
pub(crate) fn approval_subject() -> Option<(u32, u32)> {
    let connection = Connection::system().ok()?;
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "ListSessions",
            &(),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()?;

    let mut active_non_graphical = None;
    for (_, uid, _, seat, path) in sessions {
        let path = path.as_str();
        if seat.is_empty()
            || !bool::try_from(session_property(&connection, path, "Active")?).ok()?
        {
            continue;
        }

        let session_type = String::try_from(session_property(&connection, path, "Type")?).ok()?;
        let leader_pid = u32::try_from(session_property(&connection, path, "Leader")?).ok()?;
        let subject = (leader_pid, uid);
        if session_type == "x11" || session_type == "wayland" {
            return Some(subject);
        }
        active_non_graphical.get_or_insert(subject);
    }

    active_non_graphical
}

fn session_property(
    connection: &Connection,
    session_path: &str,
    property: &str,
) -> Option<OwnedValue> {
    connection
        .call_method(
            Some("org.freedesktop.login1"),
            session_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.login1.Session", property),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()
}
