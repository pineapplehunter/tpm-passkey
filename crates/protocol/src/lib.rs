//! Toolkit- and TPM-independent wire types. No credential storage or GUI code.
pub mod management;
#[cfg(test)]
mod tests;
pub mod transport;
pub use management::{CredentialTarget, ManagementRequest, ManagementResponse, value_get};
pub use transport::send_request;

pub const BUS_NAME: &str = "io.github.pineapplehunter.TpmPasskey1";
pub const DAEMON_PATH: &str = "/io/github/pineapplehunter/TpmPasskey1";
pub const DAEMON_IFACE: &str = "io.github.pineapplehunter.TpmPasskey1";
pub const AGENT_IFACE: &str = "io.github.pineapplehunter.TpmPasskey1.ApprovalAgent";
pub const AGENT_PATH: &str = "/io/github/pineapplehunter/TpmPasskey1/ApprovalAgent";
pub const ACTION_REGISTER: &str = "io.github.pineapplehunter.tpm-passkey.register-agent";
pub const ACTION_READ: &str = "io.github.pineapplehunter.tpm-passkey.read";
pub const ACTION_RECOVERY: &str = "io.github.pineapplehunter.tpm-passkey.manage-recovery";
pub const ACTION_SETTINGS: &str = "io.github.pineapplehunter.tpm-passkey.manage-settings";

/// All strings are untrusted plain text, never markup. Empty strings mean absent.
/// Operation is one of register/login/selection/reset. Zero candidates is valid
/// for selection/reset; multiple candidates must never imply an account choice.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct ApprovalContext {
    pub operation: String,
    pub rp_id: String,
    pub rp_name: String,
    pub account_name: String,
    pub account_id: String,
    pub credential_count: u32,
}

impl ApprovalContext {
    pub fn validate(&self) -> bool {
        matches!(
            self.operation.as_str(),
            "register" | "login" | "selection" | "reset"
        ) && [
            &self.rp_id,
            &self.rp_name,
            &self.account_name,
            &self.account_id,
        ]
        .into_iter()
        .all(|s| s.len() <= 2048)
            && (matches!(self.operation.as_str(), "selection" | "reset") || !self.rp_id.is_empty())
    }
}
