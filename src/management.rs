//! Privileged management dispatch. The only public transport is the system bus;
//! there is deliberately no legacy Unix socket listener or client bypass.
mod service;

/// Fixed, nonsecret diagnostics. Never forward database, TPM or crypto reports
/// over the management transport: they can contain attacker-controlled data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError {
    SetupRequired,
    AlreadyConfigured,
    CredentialsRemain,
    Authentication,
    Integrity,
    InvalidPolicy,
    NotFound,
    Timeout,
    WorkerUnavailable,
    Failed,
}
impl std::fmt::Display for ManagementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SetupRequired => "migration setup required; run tpm-passkey setup",
            Self::AlreadyConfigured => "migration setup already completed; use tpm-passkey config passphrase or config policy",
            Self::CredentialsRemain => "migration configuration missing while credentials remain; restore a trusted backup before proceeding",
            Self::Authentication => "migration authentication failed; check the current passphrase and restore a trusted backup if the problem persists",
            Self::Integrity => "stored state failed integrity validation; restore a trusted database and integrity-key backup; do not delete or replace the key",
            Self::InvalidPolicy => "invalid PCR selection; supply distinct PCR indices from 0 to 23, or --disable",
            Self::NotFound => "credential not found; refresh tpm-passkey list",
            Self::Timeout => "management deadline exceeded; inspect current state before retrying",
            Self::WorkerUnavailable => "authenticator worker unavailable; check the tpm-passkey service",
            Self::Failed => "management operation failed; check service health and trusted state backups",
        })
    }
}
impl std::error::Error for ManagementError {}
impl ManagementError {
    pub(crate) fn from_report(error: &color_eyre::Report) -> Self {
        error
            .downcast_ref::<Self>()
            .copied()
            .unwrap_or(Self::Failed)
    }
}
pub(crate) use service::dispatch_until;
pub use tpm_passkey_protocol::{
    CredentialTarget, DefaultPcrPolicyChange, ManagementRequest, ManagementResponse, value_get,
};
