//! Privileged management dispatch. The only public transport is the system bus;
//! there is deliberately no legacy Unix socket listener or client bypass.
mod service;
pub(crate) use service::dispatch_until;
pub use tpm_passkey_protocol::{
    CredentialTarget, ManagementRequest, ManagementResponse, value_get,
};
