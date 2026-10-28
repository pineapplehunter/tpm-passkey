use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};

/// Find a process subject for routing polkit prompts to the desktop agent.
/// This does not identify the sender of a HID request or authorize credentials.
/// The caller must drive this future inside the approval control scope.
pub(crate) async fn approval_subject(connection: &Connection) -> zbus::Result<Option<(u32, u32)>> {
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

    let mut active_non_graphical = None;
    for (_, uid, _, seat, path) in sessions {
        let path = path.as_str();
        if seat.is_empty() || !bool::try_from(session_property(connection, path, "Active").await?)?
        {
            continue;
        }

        let session_type = String::try_from(session_property(connection, path, "Type").await?)?;
        let leader_pid = u32::try_from(session_property(connection, path, "Leader").await?)?;
        let subject = (leader_pid, uid);
        if session_type == "x11" || session_type == "wayland" {
            return Ok(Some(subject));
        }
        active_non_graphical.get_or_insert(subject);
    }

    Ok(active_non_graphical)
}

async fn session_property(
    connection: &Connection,
    session_path: &str,
    property: &str,
) -> zbus::Result<OwnedValue> {
    connection
        .call_method(
            Some("org.freedesktop.login1"),
            session_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.login1.Session", property),
        )
        .await?
        .body()
        .deserialize()
}
