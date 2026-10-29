use crate::approval::{ApprovalControl, ApprovalOutcome};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use zbus::{Connection, zvariant::Value};

const AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Authorize the actual message sender, never an argument, session leader or PID.
/// Interaction is only management authorization, never authenticator presence.
pub(crate) async fn authorize(
    connection: &Connection,
    sender: &str,
    action: &str,
    interaction: bool,
    control: &ApprovalControl,
) -> Result<bool, ApprovalOutcome> {
    if !sender.starts_with(':') {
        return Ok(false);
    }
    let id = format!(
        "tpm-passkey-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let result = control.run(async {
        if !caller_alive(connection, sender).await { return false; }
        let mut subject = HashMap::new();
        subject.insert("name", Value::from(sender));
        let details: HashMap<&str, &str> = HashMap::new();
        let body = (("system-bus-name", subject), action, details, u32::from(interaction), &id);
        let call = connection.call_method(Some(AUTHORITY), PATH, Some(IFACE), "CheckAuthorization", &body);
        tokio::pin!(call);
        loop {
            tokio::select! {
                reply = &mut call => {
                    let authorized = reply.ok().and_then(|r| r.body().deserialize::<(bool, bool, HashMap<String, String>)>().ok())
                        .is_some_and(|(authorized, _, _)| authorized);
                    return authorized && caller_alive(connection, sender).await;
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    if !caller_alive(connection, sender).await { return false; }
                }
            }
        }
    }).await;
    if !matches!(result, Ok(true)) {
        // Same connection and cancellation ID; cleanup cannot consume a fresh
        // authorization budget or indefinitely delay CTAPHID cancellation.
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            connection.call_method(
                Some(AUTHORITY),
                PATH,
                Some(IFACE),
                "CancelCheckAuthorization",
                &(&id,),
            ),
        )
        .await;
    }
    result
}

pub(crate) async fn caller_alive(connection: &Connection, sender: &str) -> bool {
    if !sender.starts_with(':') {
        return false;
    }
    let Ok(proxy) = zbus::fdo::DBusProxy::new(connection).await else {
        return false;
    };
    let Ok(name) = sender.try_into() else {
        return false;
    };
    proxy.name_has_owner(name).await.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn actions_are_operation_specific_and_unknown_operations_are_rejected() {
        use crate::bus::management_action;
        use tpm_passkey_protocol::*;
        assert_eq!(management_action("list-credentials"), Some(ACTION_READ));
        assert_eq!(management_action("show-config"), Some(ACTION_READ));
        assert_eq!(
            management_action("verify-migration-passphrase"),
            Some(ACTION_MIGRATION)
        );
        assert_eq!(management_action("setup-migration"), Some(ACTION_MIGRATION));
        assert_eq!(
            management_action("migrate-credentials"),
            Some(ACTION_MIGRATION)
        );
        assert_eq!(
            management_action("update-pcr-policy"),
            Some(ACTION_MIGRATION)
        );
        assert_eq!(
            management_action("set-default-pcr-policy"),
            Some(ACTION_SETTINGS)
        );
        assert_eq!(management_action("unknown"), None);
    }
}
