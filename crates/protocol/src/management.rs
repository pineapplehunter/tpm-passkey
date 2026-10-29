use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// Externally tagged: decode fields directly, without Serde's adjacent-tag
// Content buffering, which would retain unguarded copies of secret strings.
#[derive(Serialize, Deserialize)]
pub enum ManagementRequest {
    #[serde(rename = "list-credentials")]
    ListCredentials,
    #[serde(rename = "credential-info")]
    CredentialInfo { local_id: u64 },
    #[serde(rename = "setup-migration")]
    SetupMigration {
        #[serde(deserialize_with = "secret")]
        passphrase: Zeroizing<String>,
        /// `None` disables PCR binding; `Some` selects SHA-256 PCRs.
        pcr_indices: Option<Vec<u32>>,
    },
    #[serde(rename = "migrate-credentials")]
    MigrateCredentials {
        #[serde(deserialize_with = "secret")]
        passphrase: Zeroizing<String>,
        pcr_indices: Option<Vec<u32>>,
        credential_ids: Vec<String>,
        /// Select the current credential set on the daemon, not a client snapshot.
        #[serde(default)]
        all_credentials: bool,
        /// Change the default only after every selected credential succeeds.
        #[serde(default)]
        default_policy_change: DefaultPcrPolicyChange,
    },
    #[serde(rename = "update-migration-passphrase")]
    UpdateMigrationPassphrase {
        #[serde(default, deserialize_with = "optional_secret")]
        old_passphrase: Option<Zeroizing<String>>,
        #[serde(deserialize_with = "secret")]
        new_passphrase: Zeroizing<String>,
    },
    #[serde(rename = "verify-migration-passphrase")]
    VerifyMigrationPassphrase {
        #[serde(deserialize_with = "secret")]
        passphrase: Zeroizing<String>,
    },
    #[serde(rename = "migrate-pcr-reference")]
    MigratePcrReference {
        #[serde(deserialize_with = "secret")]
        passphrase: Zeroizing<String>,
    },
    #[serde(rename = "update-pcr-policy")]
    UpdatePcrPolicy {
        #[serde(deserialize_with = "secret")]
        passphrase: Zeroizing<String>,
        pcr_indices: Vec<u32>,
        #[serde(flatten)]
        credential_target: CredentialTarget,
        /// Change the default only after every selected credential succeeds.
        #[serde(default)]
        default_policy_change: DefaultPcrPolicyChange,
    },
    #[serde(rename = "set-default-pcr-policy")]
    SetDefaultPcrPolicy { pcr_indices: Vec<u32> },
    #[serde(rename = "disable-default-pcr-policy")]
    DisableDefaultPcrPolicy,
    #[serde(rename = "show-config")]
    ShowConfig,
}

// Ask for a borrowed str, not deserialize_string: Ciborium's owned-string
// decoder grows an unguarded intermediate String, including on truncated input.
// The transport supplies a guarded scratch buffer as large as the whole message.
fn secret<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Zeroizing<String>, D::Error> {
    struct SecretVisitor;
    impl<'de> serde::de::Visitor<'de> for SecretVisitor {
        type Value = Zeroizing<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a secret string")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(value.to_owned()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(value))
        }
    }
    decoder.deserialize_str(SecretVisitor)
}
fn optional_secret<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    struct OptionalSecret;
    impl<'de> serde::de::Visitor<'de> for OptionalSecret {
        type Value = Option<Zeroizing<String>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional secret")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            decoder: D,
        ) -> Result<Self::Value, D::Error> {
            secret(decoder).map(Some)
        }
    }
    decoder.deserialize_option(OptionalSecret)
}

impl ManagementRequest {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::ListCredentials => "list-credentials",
            Self::CredentialInfo { .. } => "credential-info",
            Self::SetupMigration { .. } => "setup-migration",
            Self::MigrateCredentials { .. } => "migrate-credentials",
            Self::UpdateMigrationPassphrase { .. } => "update-migration-passphrase",
            Self::VerifyMigrationPassphrase { .. } => "verify-migration-passphrase",
            Self::MigratePcrReference { .. } => "migrate-pcr-reference",
            Self::UpdatePcrPolicy { .. } => "update-pcr-policy",
            Self::SetDefaultPcrPolicy { .. } => "set-default-pcr-policy",
            Self::DisableDefaultPcrPolicy => "disable-default-pcr-policy",
            Self::ShowConfig => "show-config",
        }
    }
}

impl std::fmt::Debug for ManagementRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementRequest")
            .field("operation", &self.operation())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum DefaultPcrPolicyChange {
    #[default]
    Keep,
    Set {
        pcr_indices: Vec<u32>,
    },
    Disable,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialTarget {
    All { all: bool },
    Ids { credential_ids: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ciborium::value::Value>,
}

pub fn value_get<'a>(
    value: &'a ciborium::value::Value,
    key: &str,
) -> Option<&'a ciborium::value::Value> {
    value.as_map().and_then(|map| {
        map.iter()
            .find(|(candidate, _)| candidate.as_text() == Some(key))
            .map(|(_, value)| value)
    })
}
