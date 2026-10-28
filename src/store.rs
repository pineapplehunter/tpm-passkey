use std::{
    collections::HashMap,
    fs,
    future::Future,
    path::{Path, PathBuf},
    str::FromStr,
};

use color_eyre::{
    Result,
    eyre::{WrapErr, eyre},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use p256::PublicKey;
use p256::elliptic_curve::sec1::ToSec1Point;

use crate::{
    recovery::{self, EncryptedSecret},
    tpm,
};

type HmacSha256 = Hmac<Sha256>;

pub const DEV_STORE_DIR: &str = ".tpm-passkey-store";
const CREDENTIALS_DATABASE_FILE: &str = "credentials.sqlite";
const HMAC_KEY_FILE: &str = "integrity.hmac-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredentialSummary {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub user_name: Option<String>,
    pub registered_at: String,
    pub last_used_at: Option<String>,
    pub policy_selection: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCtap2Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub discoverable: bool,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key: StoredTpmKey,
    pub policy: Option<StoredPcrPolicy>,
    pub recovery: Option<StoredRecoverySlot>,
    pub sign_count: u32,
    pub integrity_mac: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPcrPolicy {
    pub selection: String,
    pub digest: Vec<u8>,
    pub policy_ref: Option<Vec<u8>>,
    pub authority_name: Option<Vec<u8>>,
    pub authority_signature: Option<Vec<u8>>,
    pub policy_version: u32,
}

impl StoredPcrPolicy {
    pub fn current_version() -> u32 {
        1
    }

    pub fn is_version_supported(version: u32) -> bool {
        let supported: &[u32] = &[1];
        supported.contains(&version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecoverySlot {
    pub label: Option<String>,
    pub encrypted_auth: EncryptedSecret,
    pub key: StoredTpmKey,
    pub last_used: Option<String>,
    pub used_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTpmKey {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
}

impl StoredRecoverySlot {
    pub fn authority(&self) -> tpm::TpmCredential {
        tpm::TpmCredential {
            private: self.key.private.clone(),
            public: self.key.public.clone(),
            public_key_x: self.key.public_key_x.clone(),
            public_key_y: self.key.public_key_y.clone(),
            auth_value: None,
        }
    }

    pub fn unlock(
        &self,
        credential_id: &[u8],
        policy_ref: &[u8],
        passphrase: &str,
    ) -> Result<tpm::TpmCredential> {
        let aad = recovery::credential_aad(credential_id, &self.key.public, policy_ref);
        let auth = self.encrypted_auth.decrypt(passphrase, &aad)?;
        if auth.len() != 32 {
            return Err(eyre!("invalid recovery authorization length"));
        }
        let mut authority = self.authority();
        authority.auth_value = Some(auth);
        Ok(authority)
    }
}

fn sec1_encode_point(x: &[u8], y: &[u8]) -> String {
    let mut encoded = vec![0x04u8];
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&encoded)
        .expect("valid P-256 SEC.1 point")
        .to_string()
}

fn sec1_decode_point(data: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk: PublicKey = data
        .parse()
        .map_err(|e| eyre!("invalid PEM public key: {e}"))?;
    let point = pk.to_sec1_point(false);
    let x: &[u8] = point.x().ok_or_else(|| eyre!("SEC.1 point missing x"))?;
    let y: &[u8] = point.y().ok_or_else(|| eyre!("SEC.1 point missing y"))?;
    Ok((x.to_vec(), y.to_vec()))
}

#[derive(Serialize, Deserialize)]
struct TpmKeyBlob {
    private: Vec<u8>,
    public: Vec<u8>,
}

fn tpm_key_to_blob(key: &StoredTpmKey) -> Vec<u8> {
    let blob = TpmKeyBlob {
        private: key.private.clone(),
        public: key.public.clone(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&blob, &mut buf).expect("serializing TPM key blob");
    buf
}

fn tpm_key_from_blob(data: &[u8], public_key: &str) -> Result<StoredTpmKey> {
    let blob: TpmKeyBlob = ciborium::from_reader(data).wrap_err("deserializing TPM key blob")?;
    let (public_key_x, public_key_y) =
        sec1_decode_point(public_key).wrap_err("decoding SEC.1 public key point")?;
    Ok(StoredTpmKey {
        private: blob.private,
        public: blob.public,
        public_key_x,
        public_key_y,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredClientPinState {
    pub pin_salt: Vec<u8>,
    pub pin_verifier: Vec<u8>,
    pub retries: u32,
    pub integrity_mac: Option<Vec<u8>>,
}

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn credentials_database_path() -> PathBuf {
    credentials_database_path_in_dir(dev_store_dir())
}

pub fn load_ctap2_credentials() -> Result<Vec<StoredCtap2Credential>> {
    load_ctap2_credentials_from_dir(dev_store_dir())
}

pub fn load_ctap2_credentials_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Vec<StoredCtap2Credential>> {
    block_on_store(load_ctap2_credentials_async(dir.as_ref()))
}

pub fn load_credential_summaries_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Vec<StoredCredentialSummary>> {
    block_on_store(load_credential_summaries_async(dir.as_ref()))
}

pub fn save_ctap2_credentials(credentials: &[StoredCtap2Credential]) -> Result<()> {
    save_ctap2_credentials_to_dir(dev_store_dir(), credentials)
}

pub fn save_ctap2_credentials_to_dir(
    dir: impl AsRef<Path>,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    block_on_store(save_ctap2_credentials_async(dir.as_ref(), credentials))
}

pub fn update_ctap2_sign_count_in_dir(
    dir: impl AsRef<Path>,
    credential_id: &[u8],
    sign_count: u32,
) -> Result<()> {
    block_on_store(update_ctap2_sign_count_async(
        dir.as_ref(),
        credential_id,
        sign_count,
    ))
}

/// Commit a recovery-approved policy and its token usage together.
pub fn update_ctap2_policy_in_dir(
    dir: impl AsRef<Path>,
    credential_id: &[u8],
    policy: &StoredPcrPolicy,
) -> Result<(String, u64)> {
    block_on_store(update_ctap2_policy_async(
        dir.as_ref(),
        credential_id,
        policy,
    ))
}

pub fn delete_ctap2_credential_from_dir(dir: impl AsRef<Path>, credential_id: &[u8]) -> Result<()> {
    block_on_store(delete_ctap2_credential_async(dir.as_ref(), credential_id))
}

pub fn load_client_pin_state_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Option<StoredClientPinState>> {
    block_on_store(load_client_pin_state_async(dir.as_ref()))
}

pub fn save_client_pin_state_to_dir(
    dir: impl AsRef<Path>,
    state: &StoredClientPinState,
) -> Result<()> {
    block_on_store(save_client_pin_state_async(dir.as_ref(), state))
}

pub fn delete_client_pin_state_from_dir(dir: impl AsRef<Path>) -> Result<()> {
    block_on_store(delete_client_pin_state_async(dir.as_ref()))
}

/// Factory reset must not clear PIN protection before credential deletion commits,
/// nor depend on which credential rows the daemon successfully loaded into memory.
pub fn reset_authenticator_state_from_dir(dir: impl AsRef<Path>) -> Result<()> {
    block_on_store(async {
        let pool = open_database(dir.as_ref()).await?;
        let mut transaction = pool.begin().await?;
        sqlx::query!("DELETE FROM credential_metadata")
            .execute(&mut *transaction)
            .await?;
        sqlx::query!("DELETE FROM client_pin_state")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    })
}

pub fn credentials_database_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(CREDENTIALS_DATABASE_FILE)
}

pub fn load_default_pcr_policy(dir: impl AsRef<Path>) -> Result<Option<Vec<u32>>> {
    block_on_store(load_default_pcr_policy_async(dir.as_ref()))
}

async fn load_default_pcr_policy_async(dir: &Path) -> Result<Option<Vec<u32>>> {
    let pool = open_database(dir).await?;
    let row = sqlx::query("SELECT value FROM daemon_config WHERE key = 'default_pcr_policy'")
        .fetch_optional(&pool)
        .await
        .wrap_err("loading default PCR policy from database")?;

    match row {
        Some(r) => {
            let blob: Vec<u8> = r.get("value");
            let indices: Vec<u32> = ciborium::from_reader(&blob[..])
                .wrap_err("deserializing default PCR policy from database")?;
            tpm::pcr_selection_for_indices(&indices)
                .wrap_err("invalid saved default PCR selection")?;
            Ok(Some(indices))
        }
        None => Ok(None),
    }
}

pub fn save_default_pcr_policy(dir: impl AsRef<Path>, indices: &[u32]) -> Result<()> {
    tpm::pcr_selection_for_indices(indices)?;
    block_on_store(save_default_pcr_policy_async(dir.as_ref(), indices))
}

async fn save_default_pcr_policy_async(dir: &Path, indices: &[u32]) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut blob = Vec::new();
    ciborium::into_writer(indices, &mut blob).wrap_err("serializing default PCR policy")?;
    sqlx::query(
        "INSERT OR REPLACE INTO daemon_config (key, value, updated_at) VALUES ('default_pcr_policy', ?, datetime('now'))",
    )
    .bind(blob)
    .execute(&pool)
    .await
    .wrap_err("saving default PCR policy to database")?;
    Ok(())
}

/// Disabling binding removes only the default for future registrations.
pub fn clear_default_pcr_policy(dir: impl AsRef<Path>) -> Result<()> {
    block_on_store(async {
        let pool = open_database(dir.as_ref()).await?;
        sqlx::query!("DELETE FROM daemon_config WHERE key = 'default_pcr_policy'")
            .execute(&pool)
            .await?;
        Ok(())
    })
}

pub fn load_recovery_config(dir: impl AsRef<Path>) -> Result<Option<EncryptedSecret>> {
    block_on_store(async {
        let pool = open_database(dir.as_ref()).await?;
        let row = sqlx::query!("SELECT value FROM daemon_config WHERE key = 'recovery_encryption'")
            .fetch_optional(&pool)
            .await?;
        row.map(|row| {
            ciborium::from_reader(row.value.as_slice())
                .wrap_err("decoding recovery encryption configuration")
        })
        .transpose()
    })
}

/// Rotate all encrypted authorization values and their unlock configuration
/// together. A missing slot or failed write rolls back the entire change.
pub fn save_recovery_configuration(
    dir: impl AsRef<Path>,
    config: &EncryptedSecret,
    slots: &[(Vec<u8>, EncryptedSecret)],
) -> Result<()> {
    block_on_store(async {
        let pool = open_database(dir.as_ref()).await?;
        let mut tx = pool.begin().await?;
        for (id, encrypted) in slots {
            let mut blob = Vec::new();
            ciborium::into_writer(encrypted, &mut blob)
                .wrap_err("encoding recovery authorization")?;
            let result = sqlx::query!(
                "UPDATE credential_tokens SET encrypted_auth = ?1, updated_at = CURRENT_TIMESTAMP \
                 WHERE keyslot_id = (SELECT keyslot_id FROM credential_keyslots \
                                    WHERE credential_id = ?2 AND slot_kind = 'recovery') \
                   AND token_type = 'passphrase'",
                blob,
                id,
            )
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() != 1 {
                return Err(eyre!("recovery slot not found during passphrase rotation"));
            }
        }
        let mut blob = Vec::new();
        ciborium::into_writer(config, &mut blob).wrap_err("encoding recovery configuration")?;
        sqlx::query!(
            "INSERT INTO daemon_config (key, value) VALUES ('recovery_encryption', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            blob,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    })
}

async fn load_credential_summaries_async(dir: &Path) -> Result<Vec<StoredCredentialSummary>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(Vec::new());
    }

    let pool = open_database(dir).await?;
    let rows = sqlx::query!(
        "SELECT m.credential_id, m.rp_id, m.user_name, m.created_at, m.last_used_at, \
                p.policy_selection \
         FROM credential_metadata m \
         JOIN credential_keyslots p \
           ON p.credential_id = m.credential_id AND p.slot_kind = 'primary' \
         ORDER BY m.rp_id, m.credential_id",
    )
    .fetch_all(&pool)
    .await
    .wrap_err_with(|| {
        format!(
            "loading credential summaries from {}",
            database_path.display()
        )
    })?;

    Ok(rows
        .into_iter()
        .map(|row| StoredCredentialSummary {
            id: row.credential_id,
            rp_id: row.rp_id,
            user_name: row.user_name,
            registered_at: row.created_at,
            last_used_at: row.last_used_at,
            policy_selection: row.policy_selection,
        })
        .collect())
}

async fn load_ctap2_credentials_async(dir: &Path) -> Result<Vec<StoredCtap2Credential>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(Vec::new());
    }

    let pool = open_database(dir).await?;
    let rows = sqlx::query(
        "SELECT m.credential_id, m.rp_id, m.discoverable, m.user_handle, m.user_name, m.user_display_name, \
                m.sign_count, m.integrity_mac, \
                 p.policy_selection, p.policy_digest, p.policy_ref, p.authority_name, p.authority_signature, p.policy_version, \
                p.tpm_key AS primary_tpm_key, p.public_key AS primary_public_key, \
                r.slot_label AS recovery_label, \
                r.tpm_key AS recovery_tpm_key, r.public_key AS recovery_public_key, \
                 t.encrypted_auth, t.last_used AS token_last_used, t.used_count AS token_used_count \
         FROM credential_metadata m \
         JOIN credential_keyslots p \
           ON p.credential_id = m.credential_id AND p.slot_kind = 'primary' \
         LEFT JOIN credential_keyslots r \
           ON r.credential_id = m.credential_id AND r.slot_kind = 'recovery' \
         LEFT JOIN credential_tokens t ON t.keyslot_id = r.keyslot_id \
         ORDER BY m.rp_id, m.credential_id",
    )
    .fetch_all(&pool)
    .await
    .wrap_err_with(|| format!("loading credentials from {}", database_path.display()))?;

    rows.into_iter()
        .map(|row| {
            let sign_count: i64 = row.try_get("sign_count")?;
            let policy_selection: Option<String> = row.try_get("policy_selection")?;
            let policy_digest: Option<Vec<u8>> = row.try_get("policy_digest")?;
            let policy_ref: Option<Vec<u8>> = row.try_get("policy_ref")?;
            let authority_name: Option<Vec<u8>> = row.try_get("authority_name")?;
            let authority_signature: Option<Vec<u8>> = row.try_get("authority_signature")?;
            let policy_version: u32 = row
                .try_get::<i64, _>("policy_version")?
                .try_into()
                .wrap_err("invalid policy_version")?;
            let recovery_label: Option<String> = row.try_get("recovery_label")?;
            let primary_tpm_key: Vec<u8> = row.try_get("primary_tpm_key")?;
            let primary_public_key: String = row.try_get("primary_public_key")?;
            let recovery_tpm_key: Option<Vec<u8>> = row.try_get("recovery_tpm_key")?;
            let recovery_public_key: Option<String> = row.try_get("recovery_public_key")?;
            let encrypted_auth: Option<Vec<u8>> = row.try_get("encrypted_auth")?;
            let integrity_mac: Option<Vec<u8>> = row.try_get("integrity_mac")?;

            let primary_key = tpm_key_from_blob(&primary_tpm_key, &primary_public_key)?;

            let recovery = match (
                recovery_label,
                recovery_tpm_key,
                recovery_public_key,
                encrypted_auth,
            ) {
                (label, Some(tpm_key_data), Some(pub_key_data), Some(encrypted)) => {
                    let encrypted_auth = ciborium::from_reader(encrypted.as_slice())
                        .wrap_err("decoding encrypted recovery authorization")?;
                    let key = tpm_key_from_blob(&tpm_key_data, &pub_key_data)?;
                    Some(StoredRecoverySlot {
                        label,
                        encrypted_auth,
                        key,
                        last_used: row.try_get("token_last_used")?,
                        used_count: u64::try_from(row.try_get::<i64, _>("token_used_count")?)
                            .wrap_err("invalid recovery token use count")?,
                    })
                }
                (None, None, None, None) => None,
                _ => return Err(eyre!("incomplete recovery slot")),
            };

            let stored = StoredCtap2Credential {
                id: row.try_get("credential_id")?,
                rp_id: row.try_get("rp_id")?,
                discoverable: row.try_get::<i64, _>("discoverable")? != 0,
                user_handle: row.try_get("user_handle")?,
                user_name: row.try_get("user_name")?,
                user_display_name: row.try_get("user_display_name")?,
                key: primary_key,
                policy: match (policy_selection, policy_digest) {
                    (Some(selection), Some(digest)) => Some(StoredPcrPolicy {
                        selection,
                        digest,
                        policy_ref,
                        authority_name,
                        authority_signature,
                        policy_version,
                    }),
                    _ => None,
                },
                recovery,
                sign_count: u32::try_from(sign_count)
                    .wrap_err_with(|| format!("invalid sign_count {}", sign_count))?,
                integrity_mac,
            };

            if let Some(ref expected_mac) = stored.integrity_mac {
                let key = match load_or_generate_hmac_key(dir) {
                    Ok(key) => key,
                    Err(error) => {
                        log::warn!("cannot verify credential integrity: {error:?}");
                        return Ok(stored);
                    }
                };
                let computed = compute_credential_mac(&key, &stored)?;
                if computed != expected_mac as &[u8] {
                    log::error!(
                        "credential integrity check failed for rp_id={} id={}",
                        stored.rp_id,
                        hex::encode(&stored.id)
                    );
                    return Err(eyre!(
                        "credential integrity check failed for rp_id={}",
                        stored.rp_id
                    ));
                }
            }

            Ok(stored)
        })
        .collect()
}

async fn save_ctap2_credentials_async(
    dir: &Path,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut tx = pool.begin().await.wrap_err("beginning store transaction")?;
    let existing_timestamps: HashMap<Vec<u8>, (String, Option<String>)> =
        sqlx::query!("SELECT credential_id, created_at, last_used_at FROM credential_metadata")
            .fetch_all(&mut *tx)
            .await
            .wrap_err("loading existing credential timestamps")?
            .into_iter()
            .map(|row| (row.credential_id, (row.created_at, row.last_used_at)))
            .collect();

    sqlx::query!("DELETE FROM credential_metadata")
        .execute(&mut *tx)
        .await
        .wrap_err("clearing credential rows")?;

    for credential in credentials {
        let key = match load_or_generate_hmac_key(dir) {
            Ok(key) => {
                let mac = compute_credential_mac(&key, credential)?;
                Some(mac)
            }
            Err(error) => {
                log::warn!("cannot compute credential integrity MAC: {error:?}");
                None
            }
        };

        let (registered_at, last_used_at) = existing_timestamps
            .get(&credential.id)
            .map(|(registered_at, last_used_at)| {
                (Some(registered_at.as_str()), last_used_at.as_deref())
            })
            .unwrap_or((None, None));
        sqlx::query!(
            "INSERT INTO credential_metadata \
             (credential_id, rp_id, discoverable, user_handle, user_name, user_display_name, sign_count, integrity_mac, created_at, last_used_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, COALESCE(?9, CURRENT_TIMESTAMP), ?10)",
            &credential.id,
            &credential.rp_id,
            i64::from(credential.discoverable),
            &credential.user_handle,
            credential.user_name.as_deref(),
            credential.user_display_name.as_deref(),
            i64::from(credential.sign_count),
            key.as_deref(),
            registered_at,
            last_used_at,
        )
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving credential metadata for rp_id={}", credential.rp_id))?;

        let primary_tpm_key_blob = tpm_key_to_blob(&credential.key);
        let primary_public_key_blob =
            sec1_encode_point(&credential.key.public_key_x, &credential.key.public_key_y);
        sqlx::query(
            "INSERT INTO credential_keyslots \
             (credential_id, slot_kind, slot_label, policy_selection, policy_digest, policy_ref, authority_name, authority_signature, policy_version, tpm_key, public_key) \
             VALUES (?1, 'primary', NULL, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)",
        )
        .bind(&credential.id)
        .bind(credential.policy.as_ref().map(|policy| policy.selection.as_str()))
        .bind(credential.policy.as_ref().map(|policy| policy.digest.as_slice()))
        .bind(credential.policy.as_ref().and_then(|policy| policy.policy_ref.as_deref()))
        .bind(credential.policy.as_ref().and_then(|policy| policy.authority_name.as_deref()))
        .bind(credential.policy.as_ref().and_then(|policy| policy.authority_signature.as_deref()))
        .bind(primary_tpm_key_blob)
        .bind(primary_public_key_blob)
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving primary keyslot for rp_id={}", credential.rp_id))?;

        if let Some(recovery) = &credential.recovery {
            let recovery_tpm_key_blob = tpm_key_to_blob(&recovery.key);
            let recovery_public_key_blob =
                sec1_encode_point(&recovery.key.public_key_x, &recovery.key.public_key_y);
            let recovery_keyslot_id = sqlx::query(
                "INSERT INTO credential_keyslots \
                 (credential_id, slot_kind, slot_label, policy_selection, policy_digest, tpm_key, public_key) \
                 VALUES (?1, 'recovery', ?2, NULL, NULL, ?3, ?4)",
            )
            .bind(&credential.id)
            .bind(recovery.label.as_deref())
            .bind(recovery_tpm_key_blob)
            .bind(recovery_public_key_blob)
            .execute(&mut *tx)
            .await
            .wrap_err_with(|| format!("saving recovery keyslot for rp_id={}", credential.rp_id))?
            .last_insert_rowid();

            let mut encrypted_auth = Vec::new();
            ciborium::into_writer(&recovery.encrypted_auth, &mut encrypted_auth)
                .wrap_err("encoding encrypted recovery authorization")?;
            sqlx::query!(
                "INSERT INTO credential_tokens \
                 (keyslot_id, token_type, label, encrypted_auth, last_used, used_count) \
                 VALUES (?1, 'passphrase', ?2, ?3, ?4, ?5)",
                recovery_keyslot_id,
                recovery.label,
                encrypted_auth,
                recovery.last_used,
                i64::try_from(recovery.used_count)
                    .wrap_err("recovery token count exceeds SQLite range")?,
            )
            .execute(&mut *tx)
            .await
            .wrap_err_with(|| format!("saving recovery token for rp_id={}", credential.rp_id))?;
        }
    }

    tx.commit()
        .await
        .wrap_err("committing credential store transaction")
}

async fn update_ctap2_sign_count_async(
    dir: &Path,
    credential_id: &[u8],
    sign_count: u32,
) -> Result<()> {
    let pool = open_database(dir).await?;
    let result = sqlx::query!(
        "UPDATE credential_metadata \
         SET sign_count = ?1, updated_at = CURRENT_TIMESTAMP, last_used_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?2",
        i64::from(sign_count),
        credential_id,
    )
    .execute(&pool)
    .await
    .wrap_err("updating CTAP2 credential sign_count")?;

    if result.rows_affected() != 1 {
        return Err(eyre!(
            "updated {} rows while updating sign_count for credential ID length {}; expected 1",
            result.rows_affected(),
            credential_id.len()
        ));
    }

    Ok(())
}

async fn update_ctap2_policy_async(
    dir: &Path,
    credential_id: &[u8],
    policy: &StoredPcrPolicy,
) -> Result<(String, u64)> {
    let pool = open_database(dir).await?;
    let mut tx = pool.begin().await?;
    let result = sqlx::query!(
        "UPDATE credential_keyslots \
         SET policy_selection = ?1, policy_digest = ?2, policy_ref = ?3, \
             authority_name = ?4, authority_signature = ?5, updated_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?6 AND slot_kind = 'primary'",
        policy.selection,
        policy.digest,
        policy.policy_ref,
        policy.authority_name,
        policy.authority_signature,
        credential_id,
    )
    .execute(&mut *tx)
    .await
    .wrap_err("updating CTAP2 credential PCR policy")?;
    if result.rows_affected() != 1 {
        return Err(eyre!(
            "primary credential slot not found during policy update"
        ));
    }
    let usage = sqlx::query!(
        "UPDATE credential_tokens \
         SET last_used = CURRENT_TIMESTAMP, used_count = used_count + 1, updated_at = CURRENT_TIMESTAMP \
         WHERE keyslot_id = (SELECT keyslot_id FROM credential_keyslots \
                            WHERE credential_id = ?1 AND slot_kind = 'recovery') \
           AND token_type = 'passphrase' AND used_count < 9223372036854775807 \
         RETURNING last_used, used_count",
        credential_id,
    ).fetch_optional(&mut *tx).await?
        .ok_or_else(|| eyre!("recovery token missing or use count exhausted"))?;
    let last_used = usage
        .last_used
        .ok_or_else(|| eyre!("missing recovery use timestamp"))?;
    let used_count = u64::try_from(usage.used_count).wrap_err("invalid recovery use count")?;
    tx.commit().await?;
    Ok((last_used, used_count))
}

async fn delete_ctap2_credential_async(dir: &Path, credential_id: &[u8]) -> Result<()> {
    let pool = open_database(dir).await?;
    let result = sqlx::query!(
        "DELETE FROM credential_metadata WHERE credential_id = ?1",
        credential_id,
    )
    .execute(&pool)
    .await
    .wrap_err("deleting CTAP2 credential")?;
    if result.rows_affected() != 1 {
        return Err(eyre!(
            "deleted {} rows for credential ID; expected 1",
            result.rows_affected()
        ));
    }
    Ok(())
}

async fn load_client_pin_state_async(dir: &Path) -> Result<Option<StoredClientPinState>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(None);
    }

    let pool = open_database(dir).await?;
    let Some(row) = sqlx::query(
        "SELECT pin_salt, pin_verifier, retries, integrity_mac \
         FROM client_pin_state WHERE state_id = 1",
    )
    .fetch_optional(&pool)
    .await
    .wrap_err_with(|| format!("loading clientPIN state from {}", database_path.display()))?
    else {
        return Ok(None);
    };

    let retries: i64 = row.try_get("retries")?;
    let state = StoredClientPinState {
        pin_salt: row.try_get("pin_salt")?,
        pin_verifier: row.try_get("pin_verifier")?,
        retries: u32::try_from(retries).wrap_err("invalid clientPIN retry count")?,
        integrity_mac: row.try_get("integrity_mac")?,
    };

    if state.pin_salt.len() != 32 || state.pin_verifier.len() != 32 || state.retries > 8 {
        return Err(eyre!("invalid stored clientPIN state"));
    }
    let expected_mac = state
        .integrity_mac
        .as_ref()
        .ok_or_else(|| eyre!("clientPIN state is missing its integrity MAC"))?;
    let key = read_hmac_key(dir)?;
    let computed = compute_client_pin_mac(&key, &state)?;
    if !constant_time_equal(&computed, expected_mac) {
        return Err(eyre!("clientPIN state integrity check failed"));
    }

    Ok(Some(state))
}

async fn save_client_pin_state_async(dir: &Path, state: &StoredClientPinState) -> Result<()> {
    if state.pin_salt.len() != 32 || state.pin_verifier.len() != 32 || state.retries > 8 {
        return Err(eyre!("invalid clientPIN state"));
    }

    let pool = open_database(dir).await?;
    let key = load_or_generate_hmac_key(dir)?;
    let integrity_mac = compute_client_pin_mac(&key, state)?;
    sqlx::query(
        "INSERT INTO client_pin_state \
         (state_id, pin_salt, pin_verifier, retries, integrity_mac, updated_at) \
         VALUES (1, ?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)\
          ON CONFLICT(state_id) DO UPDATE SET \
            pin_salt = excluded.pin_salt, \
            pin_verifier = excluded.pin_verifier, \
            retries = excluded.retries, \
            integrity_mac = excluded.integrity_mac, \
           updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&state.pin_salt)
    .bind(&state.pin_verifier)
    .bind(i64::from(state.retries))
    .bind(integrity_mac)
    .execute(&pool)
    .await
    .wrap_err("saving clientPIN state")?;

    Ok(())
}

async fn delete_client_pin_state_async(dir: &Path) -> Result<()> {
    let pool = open_database(dir).await?;
    sqlx::query("DELETE FROM client_pin_state WHERE state_id = 1")
        .execute(&pool)
        .await
        .wrap_err("deleting clientPIN state")?;
    Ok(())
}

async fn open_database(dir: &Path) -> Result<SqlitePool> {
    fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    let database_path = credentials_database_path_in_dir(dir);
    let database_url = format!("sqlite://{}", database_path.display());
    let options = SqliteConnectOptions::from_str(&database_url)
        .wrap_err_with(|| format!("building SQLite URL for {}", database_path.display()))?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .wrap_err_with(|| {
            format!(
                "opening SQLite credential store {}",
                database_path.display()
            )
        })?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .wrap_err_with(|| format!("running migrations for {}", database_path.display()))?;

    Ok(pool)
}

fn read_hmac_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(HMAC_KEY_FILE);
    let raw =
        fs::read(&path).wrap_err_with(|| format!("reading HMAC key from {}", path.display()))?;
    let length = raw.len();
    raw.try_into().map_err(|_| {
        eyre!(
            "HMAC key file {} has wrong length (expected 32, got {})",
            path.display(),
            length
        )
    })
}

fn load_or_generate_hmac_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(HMAC_KEY_FILE);
    if path.exists() {
        read_hmac_key(dir)
    } else {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).wrap_err("generating HMAC key from system random")?;
        fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
        fs::write(&path, key)
            .wrap_err_with(|| format!("writing HMAC key to {}", path.display()))?;
        log::info!("generated new HMAC integrity key at {}", path.display());
        Ok(key)
    }
}

fn compute_credential_mac(key: &[u8; 32], credential: &StoredCtap2Credential) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).wrap_err("creating HMAC-SHA256")?;

    mac.update(&(credential.id.len() as u64).to_be_bytes());
    mac.update(&credential.id);
    mac.update(&(credential.rp_id.len() as u64).to_be_bytes());
    mac.update(credential.rp_id.as_bytes());
    mac.update(&[u8::from(credential.discoverable)]);
    mac.update(&(credential.user_handle.len() as u64).to_be_bytes());
    mac.update(&credential.user_handle);

    let user_name = credential.user_name.as_deref().unwrap_or("");
    mac.update(&(user_name.len() as u64).to_be_bytes());
    mac.update(user_name.as_bytes());

    let display_name = credential.user_display_name.as_deref().unwrap_or("");
    mac.update(&(display_name.len() as u64).to_be_bytes());
    mac.update(display_name.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_client_pin_mac(key: &[u8; 32], state: &StoredClientPinState) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).wrap_err("creating HMAC-SHA256")?;
    mac.update(&(state.pin_salt.len() as u64).to_be_bytes());
    mac.update(&state.pin_salt);
    mac.update(&(state.pin_verifier.len() as u64).to_be_bytes());
    mac.update(&state.pin_verifier);
    mac.update(&state.retries.to_be_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn block_on_store<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .wrap_err("creating SQLite store runtime")?
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn point_1() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    fn point_2() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[2u8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    fn point_3() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[3u8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    fn point_4() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[4u8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    fn point_5() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[5u8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    #[test]
    fn pcr_defaults_are_absent_or_explicit_and_invalid_saves_do_not_disable_them() {
        let dir = test_store_dir("optional-pcr-default");
        assert_eq!(load_default_pcr_policy(&dir).unwrap(), None);
        save_default_pcr_policy(&dir, &[1, 7]).unwrap();
        assert_eq!(load_default_pcr_policy(&dir).unwrap(), Some(vec![1, 7]));
        assert!(save_default_pcr_policy(&dir, &[]).is_err());
        assert!(save_default_pcr_policy(&dir, &[24]).is_err());
        assert_eq!(load_default_pcr_policy(&dir).unwrap(), Some(vec![1, 7]));
        clear_default_pcr_policy(&dir).unwrap();
        assert_eq!(load_default_pcr_policy(&dir).unwrap(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pin_loading_rejects_malformed_or_unauthenticated_state_without_creating_keys() {
        let dir = test_store_dir("pin-load-integrity");
        let valid = StoredClientPinState {
            pin_salt: vec![0x11; 32],
            pin_verifier: vec![0x22; 32],
            retries: 8,
            integrity_mac: None,
        };
        for fault in 0..4 {
            save_client_pin_state_to_dir(&dir, &valid).unwrap();
            let mut state = load_client_pin_state_from_dir(&dir).unwrap().unwrap();
            match fault {
                0 => state.integrity_mac = None,
                1 => state.integrity_mac = Some(vec![0; 32]),
                _ => {
                    if fault == 2 {
                        state.pin_salt.pop();
                    } else {
                        state.pin_verifier.pop();
                    }
                    // Even correctly authenticated malformed fields are rejected.
                    state.integrity_mac = Some(
                        compute_client_pin_mac(&read_hmac_key(&dir).unwrap(), &state).unwrap(),
                    );
                }
            }
            block_on_store(async {
                let pool = open_database(&dir).await?;
                let salt = &state.pin_salt;
                let verifier = &state.pin_verifier;
                let mac = state.integrity_mac.as_deref();
                sqlx::query!("UPDATE client_pin_state SET pin_salt = ?1, pin_verifier = ?2, integrity_mac = ?3 WHERE state_id = 1", salt, verifier, mac)
                    .execute(&pool).await?;
                Ok(())
            }).unwrap();
            assert!(load_client_pin_state_from_dir(&dir).is_err());
        }
        save_client_pin_state_to_dir(&dir, &valid).unwrap();
        fs::remove_file(dir.join(HMAC_KEY_FILE)).unwrap();
        assert!(load_client_pin_state_from_dir(&dir).is_err());
        assert!(
            !dir.join(HMAC_KEY_FILE).exists(),
            "reads must not generate replacement keys"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reset_is_atomic_and_removes_rows_not_loaded_by_the_daemon() {
        let dir = test_store_dir("atomic-reset");
        save_ctap2_credentials_to_dir(&dir, &[test_credential(vec![1], "example.test", 0)])
            .unwrap();
        save_client_pin_state_to_dir(
            &dir,
            &StoredClientPinState {
                pin_salt: vec![1; 32],
                pin_verifier: vec![2; 32],
                retries: 8,
                integrity_mac: None,
            },
        )
        .unwrap();
        save_default_pcr_policy(&dir, &[7]).unwrap();
        block_on_store(async {
            let pool = open_database(&dir).await?;
            sqlx::query!("CREATE TRIGGER stop_pin_reset BEFORE DELETE ON client_pin_state BEGIN SELECT RAISE(ABORT, 'test reset failure'); END")
                .execute(&pool).await?;
            Ok(())
        }).unwrap();
        assert!(reset_authenticator_state_from_dir(&dir).is_err());
        assert_eq!(load_ctap2_credentials_from_dir(&dir).unwrap().len(), 1);
        assert!(load_client_pin_state_from_dir(&dir).unwrap().is_some());
        block_on_store(async {
            let pool = open_database(&dir).await?;
            sqlx::query!("DROP TRIGGER IF EXISTS stop_pin_reset")
                .execute(&pool)
                .await?;
            Ok(())
        })
        .unwrap();
        reset_authenticator_state_from_dir(&dir).unwrap();
        assert!(load_ctap2_credentials_from_dir(&dir).unwrap().is_empty());
        assert!(load_client_pin_state_from_dir(&dir).unwrap().is_none());
        assert_eq!(load_default_pcr_policy(&dir).unwrap(), Some(vec![7]));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_store_loads_empty_credentials() {
        let dir = test_store_dir("missing");

        let credentials = load_ctap2_credentials_from_dir(&dir).expect("load credentials");

        assert!(credentials.is_empty());
    }

    #[test]
    fn credentials_round_trip_through_sqlite() {
        let dir = test_store_dir("ctap2-round-trip");
        let credentials = vec![StoredCtap2Credential {
            id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_owned(),
            discoverable: true,
            user_handle: vec![5, 6, 7, 8],
            user_name: Some("user".to_owned()),
            user_display_name: Some("Test User".to_owned()),
            key: StoredTpmKey {
                private: vec![9, 10],
                public: vec![11, 12],
                public_key_x: point_1().0,
                public_key_y: point_1().1,
            },
            policy: Some(StoredPcrPolicy {
                selection: "sha256:7".to_owned(),
                digest: vec![15; 32],
                policy_ref: None,
                authority_name: None,
                authority_signature: None,
                policy_version: 1,
            }),
            recovery: Some(StoredRecoverySlot {
                label: Some("backup".to_owned()),
                last_used: None,
                used_count: 0,
                encrypted_auth: recovery::UnlockedRecovery::new("round trip test phrase")
                    .unwrap()
                    .encrypt(&[17; 32], b"round-trip")
                    .unwrap(),
                key: StoredTpmKey {
                    private: vec![18, 19],
                    public: vec![20, 21],
                    public_key_x: point_2().0,
                    public_key_y: point_2().1,
                },
            }),
            sign_count: 10,
            integrity_mac: None,
        }];

        save_ctap2_credentials_to_dir(&dir, &credentials).expect("save CTAP2 credentials");
        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load CTAP2 credentials");

        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].integrity_mac.is_some());
        assert_eq!(loaded[0].integrity_mac.as_ref().map(Vec::len), Some(32));
        // Compare metadata excluding integrity_mac (which is computed at save time)
        let mut loaded_meta = loaded[0].clone();
        loaded_meta.integrity_mac = None;
        let mut saved_meta = credentials[0].clone();
        saved_meta.integrity_mac = None;
        assert_eq!(loaded_meta, saved_meta);
        assert!(credentials_database_path_in_dir(&dir).exists());
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn saving_replaces_removed_credentials() {
        let dir = test_store_dir("replace-removed");
        let first = StoredCtap2Credential {
            id: vec![1],
            rp_id: "first.example".to_owned(),
            discoverable: true,
            user_handle: vec![1],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![1],
                public: vec![2],
                public_key_x: point_3().0,
                public_key_y: point_3().1,
            },
            policy: None,
            recovery: None,
            sign_count: 1,
            integrity_mac: None,
        };
        let second = StoredCtap2Credential {
            id: vec![2],
            rp_id: "second.example".to_owned(),
            discoverable: true,
            user_handle: vec![2],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: point_4().0,
                public_key_y: point_4().1,
            },
            policy: None,
            recovery: None,
            sign_count: 2,
            integrity_mac: None,
        };

        save_ctap2_credentials_to_dir(&dir, &[first, second.clone()])
            .expect("save both credentials");
        save_ctap2_credentials_to_dir(&dir, std::slice::from_ref(&second))
            .expect("save remaining credential");

        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load credentials");

        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].integrity_mac.is_some());
        assert_eq!(loaded[0].integrity_mac.as_ref().map(Vec::len), Some(32));
        // Compare metadata excluding integrity_mac
        let mut loaded_meta = loaded[0].clone();
        loaded_meta.integrity_mac = None;
        let mut expected = second;
        expected.integrity_mac = None;
        assert_eq!(loaded_meta, expected);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn sign_count_update_changes_one_credential() {
        let dir = test_store_dir("update-sign-count");
        let first = test_credential(vec![1], "first.example", 1);
        let second = test_credential(vec![2], "second.example", 2);
        save_ctap2_credentials_to_dir(&dir, &[first.clone(), second.clone()])
            .expect("save credentials");
        let initial_summaries =
            load_credential_summaries_from_dir(&dir).expect("load initial summaries");
        let first_registered_at = initial_summaries
            .iter()
            .find(|summary| summary.id == first.id)
            .expect("first summary")
            .registered_at
            .clone();

        update_ctap2_sign_count_in_dir(&dir, &first.id, 42).expect("update sign count");

        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load credentials");
        let loaded_first = loaded
            .iter()
            .find(|credential| credential.id == first.id)
            .expect("first credential");
        let loaded_second = loaded
            .iter()
            .find(|credential| credential.id == second.id)
            .expect("second credential");

        assert_eq!(loaded_first.sign_count, 42);
        assert_eq!(loaded_second.sign_count, 2);

        let used_summaries = load_credential_summaries_from_dir(&dir).expect("load used summaries");
        let first_summary = used_summaries
            .iter()
            .find(|summary| summary.id == first.id)
            .expect("first summary");
        let second_summary = used_summaries
            .iter()
            .find(|summary| summary.id == second.id)
            .expect("second summary");
        assert_eq!(first_summary.registered_at, first_registered_at);
        assert!(first_summary.last_used_at.is_some());
        assert!(second_summary.last_used_at.is_none());

        save_ctap2_credentials_to_dir(&dir, &loaded).expect("resave credentials");
        let resaved_summaries =
            load_credential_summaries_from_dir(&dir).expect("load resaved summaries");
        let resaved_first = resaved_summaries
            .iter()
            .find(|summary| summary.id == first.id)
            .expect("resaved first summary");
        assert_eq!(resaved_first.registered_at, first_registered_at);
        assert_eq!(resaved_first.last_used_at, first_summary.last_used_at);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn sign_count_update_rejects_unknown_credential() {
        let dir = test_store_dir("update-missing-sign-count");
        save_ctap2_credentials_to_dir(&dir, &[test_credential(vec![1], "example.com", 1)])
            .expect("save credentials");

        let error =
            update_ctap2_sign_count_in_dir(&dir, &[9], 42).expect_err("reject missing credential");

        assert!(error.to_string().contains("updated 0 rows"));
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn recovery_rotation_is_atomic_and_stores_only_ciphertext() {
        let dir = test_store_dir("encrypted-recovery");
        let old = recovery::UnlockedRecovery::new("old recovery phrase").unwrap();
        let old_config = old.configuration().unwrap();
        let new = recovery::UnlockedRecovery::new("new recovery phrase").unwrap();
        let new_config = new.configuration().unwrap();
        let secret = [0xa5; 32];
        let mut credential = test_credential(vec![1], "example.com", 1);
        let key = StoredTpmKey {
            private: vec![3],
            public: vec![4],
            public_key_x: point_5().0,
            public_key_y: point_5().1,
        };
        let aad = recovery::credential_aad(&credential.id, &key.public, b"policy-ref");
        let old_encrypted = old.encrypt(&secret, &aad).unwrap();
        credential.recovery = Some(StoredRecoverySlot {
            label: None,
            key: key.clone(),
            encrypted_auth: old_encrypted.clone(),
            last_used: None,
            used_count: 0,
        });
        save_ctap2_credentials_to_dir(
            &dir,
            &[
                credential.clone(),
                test_credential(vec![2], "example.com", 0),
            ],
        )
        .unwrap();
        save_recovery_configuration(&dir, &old_config, &[]).unwrap();
        let new_encrypted = new.encrypt(&secret, &aad).unwrap();
        // Updating one valid slot followed by a missing slot must roll back both
        // the first slot and the configuration change.
        assert!(
            save_recovery_configuration(
                &dir,
                &new_config,
                &[
                    (credential.id.clone(), new_encrypted.clone()),
                    (vec![99], new_encrypted.clone()),
                ]
            )
            .is_err()
        );
        assert_eq!(load_recovery_config(&dir).unwrap(), Some(old_config));
        let loaded = load_ctap2_credentials_from_dir(&dir).unwrap();
        assert_eq!(
            loaded[0].recovery.as_ref().unwrap().encrypted_auth,
            old_encrypted
        );
        assert_eq!(loaded[0].recovery.as_ref().unwrap().last_used, None);
        assert_eq!(loaded[0].recovery.as_ref().unwrap().used_count, 0);
        let policy = StoredPcrPolicy {
            selection: "sha256:7".into(),
            digest: vec![9; 32],
            policy_ref: Some(b"policy-ref".to_vec()),
            authority_name: Some(vec![8]),
            authority_signature: Some(vec![7]),
            policy_version: 1,
        };
        let (last_used, used_count) =
            update_ctap2_policy_in_dir(&dir, &credential.id, &policy).unwrap();
        assert!(!last_used.is_empty());
        assert_eq!(used_count, 1);
        let (_, used_count) = update_ctap2_policy_in_dir(&dir, &credential.id, &policy).unwrap();
        assert_eq!(used_count, 2);
        // A primary-slot write must roll back if its recovery token is missing.
        assert!(update_ctap2_policy_in_dir(&dir, &[2], &policy).is_err());
        let loaded = load_ctap2_credentials_from_dir(&dir).unwrap();
        assert_eq!(loaded[1].policy, None);
        // Normal assertions, full saves, and phrase rotation must not add uses
        // or reset existing usage history.
        update_ctap2_sign_count_in_dir(&dir, &credential.id, 3).unwrap();
        let loaded = load_ctap2_credentials_from_dir(&dir).unwrap();
        save_ctap2_credentials_to_dir(&dir, &loaded).unwrap();
        save_recovery_configuration(&dir, &new_config, &[(credential.id.clone(), new_encrypted)])
            .unwrap();
        let loaded = load_ctap2_credentials_from_dir(&dir).unwrap();
        let slot = loaded[0].recovery.as_ref().unwrap();
        assert_eq!(slot.used_count, 2);
        assert!(slot.last_used.is_some());
        assert_eq!(slot.key, key);
        assert!(
            slot.unlock(&credential.id, b"policy-ref", "old recovery phrase")
                .is_err()
        );
        assert_eq!(
            slot.unlock(&credential.id, b"policy-ref", "new recovery phrase")
                .unwrap()
                .auth_value
                .unwrap()
                .as_slice(),
            secret
        );
        assert_eq!(load_recovery_config(&dir).unwrap(), Some(new_config));
        let serialized = tpm_key_to_blob(&slot.key);
        let fields: ciborium::value::Value = ciborium::from_reader(serialized.as_slice()).unwrap();
        let fields = fields.as_map().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(
            fields
                .iter()
                .all(|(key, _)| key.as_text() != Some("auth_value"))
        );
        let database = fs::read(credentials_database_path_in_dir(&dir)).unwrap();
        assert!(!database.windows(secret.len()).any(|bytes| bytes == secret));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_recovery_migration_discards_insecure_records() {
        let dir = test_store_dir("legacy-recovery-migration");
        fs::create_dir_all(&dir).unwrap();
        block_on_store(async {
            let options = SqliteConnectOptions::new()
                .filename(credentials_database_path_in_dir(&dir))
                .create_if_missing(true)
                .foreign_keys(true);
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await?;
            let migrations = sqlx::migrate!("./migrations");
            let old = sqlx::migrate::Migrator::with_migrations(
                migrations
                    .iter()
                    .filter(|migration| migration.version < 20261028060000)
                    .cloned()
                    .collect(),
            );
            old.run(&pool).await?;
            sqlx::raw_sql(
                "INSERT INTO credential_metadata (credential_id, rp_id, user_handle, sign_count) \
                 VALUES (X'01', 'legacy.example', X'02', 0); \
                 INSERT INTO credential_keyslots (credential_id, slot_kind, tpm_key, public_key) \
                 VALUES (X'01', 'recovery', X'03', 'legacy'); \
                 INSERT INTO credential_tokens (keyslot_id, token_type, kdf_params) \
                 VALUES (1, 'passphrase', 'plaintext-equivalent-secret'); \
                 INSERT INTO daemon_config (key, value) VALUES ('daemon_passphrase', X'04'); \
                 INSERT INTO daemon_config (key, value) VALUES ('default_pcr_policy', X'8107');",
            )
            .execute(&pool)
            .await?;
            migrations.run(&pool).await?;
            for query in [
                "SELECT count(*) FROM credential_metadata",
                "SELECT count(*) FROM credential_keyslots",
                "SELECT count(*) FROM credential_tokens",
            ] {
                let count: i64 = sqlx::query_scalar(query).fetch_one(&pool).await?;
                assert_eq!(count, 0, "old secrets left: {query}");
            }
            let old_config: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM daemon_config WHERE key = 'daemon_passphrase'",
            )
            .fetch_one(&pool)
            .await?;
            assert_eq!(old_config, 0);
            let owner_columns: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pragma_table_info('credential_metadata') WHERE name = 'user_id'",
            ).fetch_one(&pool).await?;
            assert_eq!(owner_columns, 0);
            let owner_indexes: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_schema WHERE name IN ('credential_metadata_user_id_idx', 'credential_metadata_owner_rp_discoverable_idx')",
            ).fetch_one(&pool).await?;
            assert_eq!(owner_indexes, 0);
            let default_policy: Vec<u8> = sqlx::query_scalar(
                "SELECT value FROM daemon_config WHERE key = 'default_pcr_policy'",
            )
            .fetch_one(&pool)
            .await?;
            assert_eq!(default_policy, vec![0x81, 7]);
            // Migrations are recorded and can be safely checked again.
            migrations.run(&pool).await?;
            pool.close().await;
            Ok(())
        })
        .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pcr_policy_version_support() {
        assert!(StoredPcrPolicy::is_version_supported(
            StoredPcrPolicy::current_version()
        ));
        assert!(!StoredPcrPolicy::is_version_supported(0));
        assert!(!StoredPcrPolicy::is_version_supported(2));
        assert!(!StoredPcrPolicy::is_version_supported(99));
    }

    fn test_credential(id: Vec<u8>, rp_id: &str, sign_count: u32) -> StoredCtap2Credential {
        StoredCtap2Credential {
            id,
            rp_id: rp_id.to_owned(),
            discoverable: true,
            user_handle: vec![1, 2, 3, 4],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: point_4().0,
                public_key_y: point_4().1,
            },
            policy: None,
            recovery: None,
            sign_count,
            integrity_mac: None,
        }
    }

    fn test_store_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "tpm-passkey-store-test-{name}-{}-{nonce}",
            std::process::id()
        ))
    }
}
