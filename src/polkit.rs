use std::collections::HashMap;

use color_eyre::Result;
use zbus::blocking::Connection;
use zbus::zvariant::Value;

const POLKIT_AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const POLKIT_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_ACTION_ID: &str = "io.github.pineapplehunter.tpm-passkey.approve";

/// Request approval through the desktop's polkit agent.
///
/// The active session leader is only a prompt-routing subject. Its identity is
/// not used to attribute HID requests or select credentials on this single-user
/// machine. The daemon itself is root and has no desktop authentication agent.
pub fn check_active_session() -> Result<bool> {
    let (pid, user_uid) = crate::systemd_logind::approval_subject()
        .ok_or_else(|| color_eyre::eyre::eyre!("no active session for polkit approval"))?;
    let start_time = process_start_time_ticks(pid)?;
    let conn = Connection::system()?;

    let mut subject_details: HashMap<&str, Value> = HashMap::new();
    subject_details.insert("pid", Value::from(pid));
    subject_details.insert("start-time", Value::from(start_time));
    subject_details.insert("uid", Value::from(user_uid as i32));
    let subject = ("unix-process", subject_details);

    let empty_details: HashMap<&str, &str> = HashMap::new();
    // AllowUserInteraction = 0x1 — lets polkit show an auth dialog
    let flags = 1u32;
    let cancellation_id = String::new();

    let result: (bool, bool, HashMap<String, String>) = conn
        .call_method(
            Some(POLKIT_AUTHORITY),
            POLKIT_AUTHORITY_PATH,
            Some(POLKIT_AUTHORITY_IFACE),
            "CheckAuthorization",
            &(
                subject,
                POLKIT_ACTION_ID,
                empty_details,
                flags,
                cancellation_id,
            ),
        )?
        .body()
        .deserialize()?;

    Ok(result.0)
}

/// Read the process start time in clock ticks since boot from `/proc`.
fn process_start_time_ticks(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_comm = stat
        .rfind(')')
        .ok_or_else(|| color_eyre::eyre::eyre!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat[after_comm + 2..].split_whitespace().collect();
    fields
        .get(19)
        .ok_or_else(|| color_eyre::eyre::eyre!("missing starttime in /proc/{pid}/stat"))?
        .parse()
        .map_err(Into::into)
}
