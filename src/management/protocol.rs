use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "params")]
pub enum ManagementRequest {
    #[serde(rename = "list-credentials")]
    ListCredentials,
    #[serde(rename = "update-passphrase")]
    UpdatePassphrase {
        #[serde(default)]
        old_passphrase: Option<String>,
        new_passphrase: String,
    },
    #[serde(rename = "unlock-recovery")]
    UnlockRecovery { passphrase: String },
    #[serde(rename = "update-pcr-reference")]
    UpdatePcrReference { passphrase: String },
    #[serde(rename = "update-pcr-policy")]
    UpdatePcrPolicy {
        passphrase: String,
        pcr_indices: Vec<u32>,
        #[serde(flatten)]
        credential_target: CredentialTarget,
    },
    #[serde(rename = "set-default-pcr-policy")]
    SetDefaultPcrPolicy { pcr_indices: Vec<u32> },
    #[serde(rename = "show-config")]
    ShowConfig,
}

impl Drop for ManagementRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::UpdatePassphrase {
                old_passphrase,
                new_passphrase,
            } => {
                old_passphrase.zeroize();
                new_passphrase.zeroize();
            }
            Self::UnlockRecovery { passphrase }
            | Self::UpdatePcrReference { passphrase }
            | Self::UpdatePcrPolicy { passphrase, .. } => passphrase.zeroize(),
            _ => {}
        }
    }
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
