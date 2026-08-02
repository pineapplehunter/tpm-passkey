use crate::{store, tpm};

/// Credential model used by CTAP command handling.
///
/// Persistence-specific encoding remains in `store`; conversions at this
/// boundary keep storage representation details out of protocol handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub discoverable: bool,
    pub user_id: Option<u32>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key: tpm::TpmCredential,
    pub policy: Option<store::StoredPcrPolicy>,
    pub recovery: Option<store::StoredRecoverySlot>,
    pub sign_count: u32,
}

impl From<store::StoredCtap2Credential> for Credential {
    fn from(stored: store::StoredCtap2Credential) -> Self {
        Self {
            id: stored.id,
            rp_id: stored.rp_id,
            discoverable: stored.discoverable,
            user_id: stored.user_id,
            user_handle: stored.user_handle,
            user_name: stored.user_name,
            user_display_name: stored.user_display_name,
            key: tpm::TpmCredential {
                private: stored.key.private,
                public: stored.key.public,
                public_key_x: stored.key.public_key_x,
                public_key_y: stored.key.public_key_y,
                auth_value: stored.key.auth_value,
            },
            policy: stored.policy,
            recovery: stored.recovery,
            sign_count: stored.sign_count,
        }
    }
}

impl From<&Credential> for store::StoredCtap2Credential {
    fn from(credential: &Credential) -> Self {
        Self {
            id: credential.id.clone(),
            rp_id: credential.rp_id.clone(),
            discoverable: credential.discoverable,
            user_id: credential.user_id,
            user_handle: credential.user_handle.clone(),
            user_name: credential.user_name.clone(),
            user_display_name: credential.user_display_name.clone(),
            key: store::StoredTpmKey {
                private: credential.key.private.clone(),
                public: credential.key.public.clone(),
                public_key_x: credential.key.public_key_x.clone(),
                public_key_y: credential.key.public_key_y.clone(),
                auth_value: credential.key.auth_value.clone(),
            },
            policy: credential.policy.clone(),
            recovery: credential.recovery.clone(),
            sign_count: credential.sign_count,
            integrity_mac: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_conversion_preserves_protocol_fields() {
        let stored = store::StoredCtap2Credential {
            id: vec![1, 2, 3],
            rp_id: "example.com".to_owned(),
            discoverable: true,
            user_id: Some(1000),
            user_handle: vec![4, 5],
            user_name: Some("alice".to_owned()),
            user_display_name: Some("Alice".to_owned()),
            key: store::StoredTpmKey {
                private: vec![6],
                public: vec![7],
                public_key_x: vec![8; 32],
                public_key_y: vec![9; 32],
                auth_value: Some(vec![10]),
            },
            policy: None,
            recovery: None,
            sign_count: 42,
            integrity_mac: Some(vec![11; 32]),
        };

        let credential = Credential::from(stored.clone());
        let round_trip = store::StoredCtap2Credential::from(&credential);

        assert_eq!(round_trip.id, stored.id);
        assert_eq!(round_trip.rp_id, stored.rp_id);
        assert_eq!(round_trip.discoverable, stored.discoverable);
        assert_eq!(round_trip.user_id, stored.user_id);
        assert_eq!(round_trip.user_handle, stored.user_handle);
        assert_eq!(round_trip.key.private, stored.key.private);
        assert_eq!(round_trip.key.auth_value, stored.key.auth_value);
        assert_eq!(round_trip.sign_count, stored.sign_count);
        assert_eq!(round_trip.integrity_mac, None);
    }
}
