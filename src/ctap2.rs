use std::{
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use bitflags::bitflags;
use color_eyre::eyre::WrapErr;
use zeroize::Zeroize;

use crate::{approval, session, store, tpm};
use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt};
use cbc::cipher::{KeyIvInit, block_padding::NoPadding};
use ciborium::{cbor, value::Value};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::Generate};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

const PIN_UV_AUTH_PROTOCOL: u64 = 2;
const PIN_RETRIES: u32 = 8;
const PIN_KDF_ROUNDS: u32 = 100_000;
const MAX_RESIDENT_CREDENTIALS: usize = 128;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Ctap2PermissionFlags: u8 {
        const MAKE_CREDENTIAL = 1 << 0;
        const GET_ASSERTION = 1 << 1;
        const CREDENTIAL_MANAGEMENT = 1 << 2;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    GetNextAssertion = 0x08,
    Reset = 0x07,
    CredentialManagement = 0x0a,
    Selection = 0x0b,
    BioEnrollment = 0x09,
    LargeBlobs = 0x0c,
    Config = 0x0d,
    BioEnrollmentPreview = 0x40,
    CredentialManagementPreview = 0x41,
}

#[derive(Debug)]
pub struct UnknownCtapCommandError;

impl std::fmt::Display for UnknownCtapCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for UnknownCtapCommandError {}

impl TryFrom<u8> for Ctap2Command {
    type Error = UnknownCtapCommandError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::MakeCredential,
            0x02 => Self::GetAssertion,
            0x04 => Self::GetInfo,
            0x06 => Self::ClientPin,
            0x07 => Self::Reset,
            0x08 => Self::GetNextAssertion,
            0x09 => Self::BioEnrollment,
            0x0a => Self::CredentialManagement,
            0x0b => Self::Selection,
            0x0c => Self::LargeBlobs,
            0x0d => Self::Config,
            0x40 => Self::BioEnrollmentPreview,
            0x41 => Self::CredentialManagementPreview,
            _ => return Err(UnknownCtapCommandError),
        })
    }
}

impl From<Ctap2Command> for u8 {
    fn from(value: Ctap2Command) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ErrorStatus {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    UnsupportedOption = 0x2b,
    NoCredentials = 0x2e,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinNotSet = 0x35,
    PinPolicyViolation = 0x37,
}

impl From<ErrorStatus> for u8 {
    fn from(status: ErrorStatus) -> Self {
        status as u8
    }
}

const COSE_ALG_ES256: i64 = -7;
pub const AAGUID: [u8; 16] = [
    0x6c, 0x74, 0x70, 0x6d, 0xf1, 0xd0, 0x42, 0x00, 0x80, 0x01, 0x54, 0x50, 0x4d, 0x46, 0x49, 0x44,
];

pub struct Authenticator {
    store_dir: PathBuf,
    tpm_path: Option<PathBuf>,
    tpm: Option<tpm::Tpm>,
    session: session::SessionContext,
    credentials: Vec<Credential>,
    pending_assertion: Option<PendingAssertion>,
    client_pin: Option<ClientPinState>,
    key_agreement: Option<EphemeralSecret>,
    pin_uv_auth_token: Option<PinUvAuthToken>,
    /// Set when `authenticatorSelection` (or a UV gesture) satisfied user
    /// verification for the current transaction. CTAP2.1 routes UV through
    /// `authenticatorSelection` when the authenticator advertises `uv` but
    /// has no clientPIN; the resulting UV must be reflected in the auth-data
    /// flags of the following makeCredential / getAssertion.
    uv_satisfied: bool,
    management: Option<ManagementState>,
}

#[derive(Debug, Clone)]
struct ClientPinState {
    pin_salt: Vec<u8>,
    pin_verifier: Vec<u8>,
    retries: u32,
}

#[derive(Debug, Clone)]
struct PinUvAuthToken {
    value: Vec<u8>,
    permissions: Ctap2PermissionFlags,
    rp_id: Option<String>,
    issued_at: Instant,
}

struct ManagementState {
    rp_indexes: Vec<usize>,
    rp_position: usize,
    credential_indexes: Vec<usize>,
    credential_position: usize,
    session_uid: Option<u32>,
    created_at: Instant,
}

struct PendingAssertion {
    rp_id: String,
    client_data_hash: Vec<u8>,
    credential_indexes: Vec<usize>,
    total_credentials: usize,
    created_at: Instant,
    session_uid: Option<u32>,
    user_presence: bool,
    user_verified: bool,
}

struct Credential {
    id: Vec<u8>,
    rp_id: String,
    discoverable: bool,
    user_id: Option<u32>,
    user_handle: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    key: tpm::TpmCredential,
    policy: Option<store::StoredPcrPolicy>,
    recovery: Option<store::StoredRecoverySlot>,
    sign_count: u32,
}

impl Authenticator {
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        let session = session::SessionContext::detect();
        let tpm = None;
        let credentials = Self::load_credentials_from_disk(&store_dir, session.uid);
        log::info!("loaded {} TPM-backed CTAP2 credentials", credentials.len());
        let client_pin = match store::load_client_pin_state_from_dir(&store_dir) {
            Ok(Some(state)) => Some(ClientPinState {
                pin_salt: state.pin_salt,
                pin_verifier: state.pin_verifier,
                retries: state.retries,
            }),
            Ok(None) => None,
            Err(error) => {
                log::warn!("failed to load clientPIN state: {error:?}");
                None
            }
        };

        Self {
            store_dir,
            tpm_path,
            tpm,
            session,
            credentials,
            pending_assertion: None,
            client_pin,
            key_agreement: None,
            pin_uv_auth_token: None,
            uv_satisfied: false,
            management: None,
        }
    }

    fn load_credentials_from_disk(store_dir: &PathBuf, uid: Option<u32>) -> Vec<Credential> {
        match store::load_ctap2_credentials_from_dir(store_dir, uid) {
            Ok(credentials) => credentials
                .into_iter()
                .map(|credential| Credential {
                    id: credential.id,
                    rp_id: credential.rp_id,
                    discoverable: credential.discoverable,
                    user_id: credential.user_id,
                    user_handle: credential.user_handle,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key: tpm::TpmCredential {
                        private: credential.key.private,
                        public: credential.key.public,
                        public_key_x: credential.key.public_key_x,
                        public_key_y: credential.key.public_key_y,
                        auth_value: credential.key.auth_value,
                    },
                    policy: credential.policy,
                    recovery: credential.recovery,
                    sign_count: credential.sign_count,
                })
                .collect(),
            Err(error) => {
                log::warn!("failed to reload CTAP2 credential store: {error:?}");
                Vec::new()
            }
        }
    }

    pub fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        let Some((&command, body)) = payload.split_first() else {
            return error_response(ErrorStatus::InvalidCommand);
        };

        let Ok(command) = Ctap2Command::try_from(command) else {
            log::info!("ctap2 command: unknown");
            return error_response(ErrorStatus::InvalidCommand);
        };

        if !matches!(
            command,
            Ctap2Command::GetNextAssertion | Ctap2Command::CredentialManagement
        ) {
            self.pending_assertion = None;
        }
        if !matches!(command, Ctap2Command::CredentialManagement) {
            self.management = None;
        }

        log::info!("ctap2 command: {}", command_name(command));

        #[cfg(not(test))]
        {
            if matches!(
                command,
                Ctap2Command::MakeCredential
                    | Ctap2Command::GetAssertion
                    | Ctap2Command::GetNextAssertion
                    | Ctap2Command::CredentialManagement
            ) {
                match store::load_daemon_passphrase_from_dir(&self.store_dir) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        // No recovery passphrase set: registration/assertion are
                        // still allowed; credentials simply won't carry
                        // passphrase-backed recovery material. This keeps a fresh
                        // authenticator usable out of the box instead of denying
                        // every operation until a passphrase is configured.
                        log::error!(
                            "daemon passphrase not set; credentials will be created without recovery material"
                        );
                    }
                    Err(e) => {
                        log::error!("failed to check daemon passphrase: {e}");
                        return error_response(ErrorStatus::OperationDenied);
                    }
                }
            }
        }

        match match command {
            Ctap2Command::GetInfo => Ok(get_info_response(self.client_pin.is_some())),
            Ctap2Command::ClientPin => self.client_pin(body),
            Ctap2Command::MakeCredential => self.make_credential(body),
            Ctap2Command::GetAssertion => self.get_assertion(body),
            Ctap2Command::GetNextAssertion => self.get_next_assertion(body),
            Ctap2Command::CredentialManagement | Ctap2Command::CredentialManagementPreview => {
                self.credential_management(body)
            }
            Ctap2Command::Reset => self.reset(),
            Ctap2Command::Selection => self.selection(),
            Ctap2Command::BioEnrollment | Ctap2Command::BioEnrollmentPreview => {
                self.bio_enrollment(body)
            }
            Ctap2Command::LargeBlobs => self.large_blobs(body),
            Ctap2Command::Config => self.config(body),
        } {
            Ok(response) => response,
            Err(status) => error_response(status),
        }
    }

    pub fn cancel_pending(&mut self) {
        self.pending_assertion = None;
        self.management = None;
        self.pin_uv_auth_token = None;
        self.key_agreement = None;
        self.uv_satisfied = false;
    }

    /// authenticatorReset (0x07): factory-resets the authenticator, deleting all
    /// credentials and clearing the configured PIN. CTAP2.2 §6.6 requires user
    /// presence (and, when set, alwaysUv) before performing the reset.
    fn reset(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        if !self.assertion_approved("reset") {
            return Err(ErrorStatus::OperationDenied);
        }
        if !self.client_pin.is_none() {
            let _ = store::delete_client_pin_state_from_dir(&self.store_dir);
            self.client_pin = None;
            self.key_agreement = None;
            self.pin_uv_auth_token = None;
        }
        for credential in &self.credentials {
            let _ = store::delete_ctap2_credential_from_dir(&self.store_dir, &credential.id);
        }
        self.credentials.clear();
        self.pending_assertion = None;
        self.management = None;
        Ok(encode_response(Value::Map(Vec::new())))
    }

    /// authenticatorSelection (0x11/0x0B): returns an empty success response once
    /// the user has given consent. CTAP2.2 §6.9. The actual user gesture is
    /// collected by the transport/UI; here we just confirm approval.
    fn selection(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        if !self.assertion_approved("selection") {
            return Err(ErrorStatus::OperationDenied);
        }
        // CTAP2.1 uses authenticatorSelection as the UV gesture when the
        // authenticator advertises `uv` but has no clientPIN. Record that UV
        // was satisfied so the following makeCredential / getAssertion can set
        // the UV flag in their auth-data.
        self.uv_satisfied = true;
        Ok(encode_response(Value::Map(Vec::new())))
    }

    /// authenticatorBioEnrollment (0x09): biometric enrollment management.
    /// This authenticator has no built-in biometric user verification method,
    /// so the command is not supported. CTAP2.2 §6.7.
    fn bio_enrollment(&mut self, _body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        Err(ErrorStatus::InvalidCommand)
    }

    /// authenticatorLargeBlobs (0x0C): large blob storage (credBlob / largeBlob
    /// extensions). Not yet implemented. CTAP2.2 §6.10.
    fn large_blobs(&mut self, _body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        Err(ErrorStatus::InvalidCommand)
    }

    /// authenticatorConfig (0x0D): authenticator configuration (enterprise
    /// attestation, alwaysUv, minPINLength). Not yet implemented. CTAP2.2 §6.11.
    fn config(&mut self, _body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        Err(ErrorStatus::InvalidCommand)
    }

    fn make_credential(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let client_data_hash = map_bytes(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let rp = map_map(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        let user = map_map(&request, 3).ok_or(ErrorStatus::MissingParameter)?;
        let params = map_array(&request, 4).ok_or(ErrorStatus::MissingParameter)?;
        let cred_props_requested = map_map(&request, 6)
            .is_some_and(|extensions| map_bool(extensions, "credProps") == Some(true));
        validate_attestation_conveyance(map_text(&request, 8))?;

        if !params.iter().any(supports_es256) {
            return Err(ErrorStatus::UnsupportedAlgorithm);
        }

        let rp_id = map_text(rp, "id").ok_or(ErrorStatus::MissingParameter)?;
        let rp_name = map_text(rp, "name");
        let user_handle = map_bytes(user, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");
        let make_credential_message = [client_data_hash, rp_id.as_bytes()].concat();
        let user_verified = self.validate_pin_uv_auth(
            map_integer(&request, 9),
            map_bytes(&request, 8),
            &make_credential_message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some(rp_id),
        )?;
        let options = map_map(&request, 7);
        if let Some(options) = options {
            log::debug!("makeCredential options: {options:?}");
        }
        validate_make_credential_options(options)?;
        let uv_requested = options.is_some_and(|options| map_bool(options, "uv") == Some(true));
        let discoverable = options.and_then(|options| map_bool(options, "rk")) == Some(true)
            || options.and_then(|options| map_bool(options, "requireResidentKey")) == Some(true)
            || options
                .and_then(|options| map_text(options, "residentKey"))
                .is_some_and(|value| value != "discouraged");
        validate_credential_descriptor_list(map_array(&request, 5))?;
        if excluded_credential_exists(&self.credentials, rp_id, map_array(&request, 5)) {
            log::info!("makeCredential excluded existing credential for rp_id={rp_id}");
            return Err(ErrorStatus::CredentialExcluded);
        }

        if !self.session.verify_matches_current() {
            log::error!("session changed before registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        if !approval::approve(
            &format!(
                "Register a new passkey for {} as {}",
                display_rp_label(rp_name, rp_id),
                user_display_name.or(user_name).unwrap_or("unknown user")
            ),
            &self.session,
        ) {
            return Err(ErrorStatus::OperationDenied);
        }
        let user_verified = user_verified || uv_requested || self.uv_satisfied;

        if !self.session.verify_matches_current() {
            log::error!("session changed during registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        let owner_uid = self.session.uid;
        let daemon_passphrase = match store::load_daemon_passphrase_from_dir(&self.store_dir) {
            Ok(Some((salt, hash, kdf))) => Some((salt, hash, kdf)),
            _ => None,
        };
        let pcr_indices = store::load_default_pcr_policy(&self.store_dir)
            .map_err(|error| {
                log::warn!("failed to load default PCR policy: {error:?}");
                ErrorStatus::OperationDenied
            })?
            .unwrap_or_else(|| vec![7]);
        let Some(tpm) = self.ensure_tpm() else {
            log::warn!("cannot create CTAP2 credential without TPM context");
            return Err(ErrorStatus::OperationDenied);
        };
        tpm.set_pcr_indices(&pcr_indices).map_err(|error| {
            log::warn!("invalid default PCR policy: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        let mut credential_id = vec![0u8; 32];
        fill_random(&mut credential_id);
        let recovery_material = match daemon_passphrase {
            Some((salt, hash, kdf)) => {
                match tpm.create_recovery_material_with_hash(None, salt, hash, kdf) {
                    Ok(material) => Some(material),
                    Err(error) => {
                        log::warn!("failed to create TPM recovery material: {error:?}");
                        return Err(ErrorStatus::OperationDenied);
                    }
                }
            }
            None => None,
        };
        let mut policy = match tpm.create_secure_boot_policy() {
            Ok(policy) => policy,
            Err(error) => {
                log::warn!(
                    "failed to create secure-boot PCR policy for CTAP2 credential: {error:?}"
                );
                return Err(ErrorStatus::OperationDenied);
            }
        };
        if let Some(material) = &recovery_material {
            let policy_ref = tpm::credential_policy_ref(&credential_id, owner_uid);
            policy = match tpm.create_authorized_policy(&policy, &material.key, &policy_ref) {
                Ok(policy) => policy,
                Err(error) => {
                    log::warn!("failed to authorize TPM PCR policy: {error:?}");
                    return Err(ErrorStatus::OperationDenied);
                }
            };
        }
        let key = match tpm.create_credential_key_with_policy(Some(&policy)) {
            Ok(credential) => credential,
            Err(error) => {
                log::warn!("failed to create TPM-backed CTAP2 credential key: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };
        log::info!("created TPM-backed CTAP2 credential key");
        let recovery = recovery_material.map(|material| store::StoredRecoverySlot {
            label: material.label,
            passphrase_salt: material.passphrase_salt,
            passphrase_hash: material.passphrase_hash,
            kdf: material.kdf,
            key: store::StoredTpmKey {
                private: material.key.private,
                public: material.key.public,
                public_key_x: material.key.public_key_x,
                public_key_y: material.key.public_key_y,
                auth_value: material.key.auth_value,
            },
        });
        let public_key = cose_credential_public_key(&key);

        let extensions = cred_props_requested.then(|| cred_props_extension(discoverable));
        let auth_data = make_auth_data(
            rp_id,
            0x41 | if user_verified { 0x04 } else { 0 },
            0,
            Some((&credential_id, &public_key)),
            extensions.as_ref(),
        );
        self.credentials.push(Credential {
            id: credential_id,
            rp_id: rp_id.to_owned(),
            discoverable,
            user_id: self.session.uid,
            user_handle: user_handle.to_vec(),
            user_name: user_name.map(str::to_owned),
            user_display_name: user_display_name.map(str::to_owned),
            key,
            policy: Some(store::StoredPcrPolicy {
                selection: policy.selection,
                digest: policy.digest,
                policy_ref: policy.policy_ref,
                authority_name: policy.authority_name,
                authority_signature: policy.authority_signature,
                policy_version: store::StoredPcrPolicy::current_version(),
            }),
            recovery,
            sign_count: 0,
        });
        self.save_credentials();

        log::info!(
            "created TPM-backed credential rp_id={} total_credentials={}",
            rp_id,
            self.credentials.len()
        );

        let response = encode_response(
            cbor!({
                1 => "none",
                2 => Value::Bytes(auth_data),
                3 => {},
            })
            .unwrap(),
        );
        log::debug!(
            "makeCredential response ({} bytes): {}",
            response.len(),
            hex::encode(&response)
        );
        Ok(response)
    }

    fn get_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let rp_id = map_text(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        let client_data_hash = map_bytes(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let user_verified = self.validate_pin_uv_auth(
            map_integer(&request, 7),
            map_bytes(&request, 6),
            client_data_hash,
            Ctap2PermissionFlags::GET_ASSERTION,
            Some(rp_id),
        )?;
        let allow_list = map_array(&request, 3);
        let options = map_map(&request, 5);
        validate_get_assertion_options(options)?;
        let uv_requested = options.is_some_and(|options| map_bool(options, "uv") == Some(true));
        let user_presence = options.and_then(|options| map_bool(options, "up")) != Some(false);
        validate_credential_descriptor_list(allow_list)?;

        // Reload credentials from disk when running as daemon (tpm_path is set)
        // to pick up management-side modifications (e.g., update-pcr-reference).
        if self.tpm_path.is_some() {
            self.credentials = Self::load_credentials_from_disk(&self.store_dir, self.session.uid);
        }
        let credential_indexes = matching_credential_indexes(&self.credentials, rp_id, allow_list);
        let Some((&credential_index, remaining_indexes)) = credential_indexes.split_first() else {
            return Err(ErrorStatus::NoCredentials);
        };

        if (user_presence || uv_requested) && !self.assertion_approved(rp_id) {
            return Err(ErrorStatus::OperationDenied);
        }
        let user_verified = user_verified || uv_requested || self.uv_satisfied;

        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: rp_id.to_owned(),
                client_data_hash: client_data_hash.to_vec(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: credential_indexes.len(),
                created_at: Instant::now(),
                session_uid: self.session.uid,
                user_presence,
                user_verified,
            })
        };

        let (auth_data, user, credential_id, key, policy, authority, rp_log, sign_count) = {
            let credential = &self.credentials[credential_index];
            let sign_count = credential.sign_count.saturating_add(1);
            let auth_data = make_auth_data(
                &credential.rp_id,
                (if user_presence { 0x01 } else { 0 }) | (if user_verified { 0x04 } else { 0 }),
                sign_count,
                None,
                None,
            );

            let mut user = vec![(
                Value::Text("id".to_owned()),
                Value::Bytes(credential.user_handle.clone()),
            )];
            if user_verified {
                if let Some(name) = &credential.user_name {
                    user.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
                }
                if let Some(display_name) = &credential.user_display_name {
                    user.push((
                        Value::Text("displayName".to_owned()),
                        Value::Text(display_name.clone()),
                    ));
                }
            }

            (
                auth_data,
                user,
                credential.id.clone(),
                credential.key.clone(),
                credential.policy.clone(),
                credential.recovery.clone(),
                credential.rp_id.clone(),
                sign_count,
            )
        };

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash);
        let signature = match sign_credential(
            self,
            &key,
            policy.as_ref(),
            authority.as_ref(),
            &signed_data,
        ) {
            Ok(signature) => signature,
            Err(error) => {
                log::warn!("failed to sign CTAP2 assertion: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };

        if let Err(error) =
            store::update_ctap2_sign_count_in_dir(&self.store_dir, &credential_id, sign_count)
        {
            log::warn!(
                "failed to persist CTAP2 assertion sign_count for rp_id={}: {error:?}",
                rp_log
            );
            return Err(ErrorStatus::OperationDenied);
        }

        self.credentials[credential_index].sign_count = sign_count;
        log::info!(
            "asserting credential rp_id={} sign_count={}",
            rp_log,
            sign_count
        );

        Ok(encode_assertion_response(
            credential_id,
            auth_data,
            signature,
            user,
            credential_indexes.len(),
        ))
    }

    fn get_next_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        if !body.is_empty() {
            return Err(ErrorStatus::InvalidCbor);
        }

        let Some(pending) = self.pending_assertion.take() else {
            return Err(ErrorStatus::NoCredentials);
        };

        if pending.created_at.elapsed() > Duration::from_secs(30)
            || pending.session_uid != self.session.uid
            || !self.session.verify_matches_current()
        {
            return Err(ErrorStatus::OperationDenied);
        }

        let Some((&credential_index, remaining_indexes)) = pending.credential_indexes.split_first()
        else {
            return Err(ErrorStatus::NoCredentials);
        };

        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: pending.rp_id.clone(),
                client_data_hash: pending.client_data_hash.clone(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: pending.total_credentials,
                created_at: pending.created_at,
                session_uid: pending.session_uid,
                user_presence: pending.user_presence,
                user_verified: pending.user_verified,
            })
        };

        let credential = &self.credentials[credential_index];
        let sign_count = credential.sign_count.saturating_add(1);
        let auth_data = make_auth_data(
            &credential.rp_id,
            (if pending.user_presence { 0x01 } else { 0 })
                | (if pending.user_verified { 0x04 } else { 0 }),
            sign_count,
            None,
            None,
        );
        let credential_id = credential.id.clone();
        let rp_log = credential.rp_id.clone();
        let credential_key = credential.key.clone();
        let credential_policy = credential.policy.clone();
        let credential_authority = credential.recovery.clone();
        let user_handle = credential.user_handle.clone();
        let user_name = credential.user_name.clone();
        let user_display_name = credential.user_display_name.clone();
        let mut user = vec![(Value::Text("id".to_owned()), Value::Bytes(user_handle))];
        if pending.user_verified {
            if let Some(name) = &user_name {
                user.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
            }
            if let Some(display_name) = &user_display_name {
                user.push((
                    Value::Text("displayName".to_owned()),
                    Value::Text(display_name.clone()),
                ));
            }
        }

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&pending.client_data_hash);
        let signature = match sign_credential(
            self,
            &credential_key,
            credential_policy.as_ref(),
            credential_authority.as_ref(),
            &signed_data,
        ) {
            Ok(signature) => signature,
            Err(error) => {
                log::warn!("failed to sign CTAP2 next assertion: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };

        if let Err(error) =
            store::update_ctap2_sign_count_in_dir(&self.store_dir, &credential_id, sign_count)
        {
            log::warn!(
                "failed to persist CTAP2 next assertion sign_count for rp_id={}: {error:?}",
                rp_log
            );
            return Err(ErrorStatus::OperationDenied);
        }

        self.credentials[credential_index].sign_count = sign_count;

        Ok(encode_assertion_response(
            credential_id,
            auth_data,
            signature,
            user,
            0,
        ))
    }

    fn client_pin(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;
        validate_pin_uv_protocol(map_integer(&request, 1))?;
        let sub_command = map_integer(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        let key_agreement = map_map(&request, 3);

        match sub_command {
            1 => {
                if map_value(&request, 3).is_some() || map_value(&request, 4).is_some() {
                    return Err(ErrorStatus::InvalidParameter);
                }
                let retries = i64::from(
                    self.client_pin
                        .as_ref()
                        .map_or(PIN_RETRIES, |pin| pin.retries),
                );
                Ok(encode_response(
                    cbor!({
                        3 => retries,
                    })
                    .unwrap(),
                ))
            }
            2 => {
                if map_value(&request, 3).is_some() || map_value(&request, 4).is_some() {
                    return Err(ErrorStatus::InvalidParameter);
                }
                self.key_agreement = Some(EphemeralSecret::generate());
                Ok(key_agreement_response(
                    self.key_agreement.as_ref().expect("just generated"),
                ))
            }
            3 => {
                let (new_pin_enc, pin_uv_auth_param) = if let Some(params) = map_map(&request, 4) {
                    (map_bytes(params, 1), map_bytes(params, 2))
                } else {
                    (map_bytes(&request, 5), map_bytes(&request, 4))
                };
                self.set_pin(
                    key_agreement,
                    new_pin_enc.ok_or(ErrorStatus::MissingParameter)?,
                    pin_uv_auth_param.ok_or(ErrorStatus::MissingParameter)?,
                )
            }
            4 => {
                let (new_pin_enc, pin_hash_enc, pin_uv_auth_param) =
                    if let Some(params) = map_map(&request, 4) {
                        (
                            map_bytes(params, 1),
                            map_bytes(params, 2),
                            map_bytes(params, 3),
                        )
                    } else {
                        (
                            map_bytes(&request, 5),
                            map_bytes(&request, 6),
                            map_bytes(&request, 4),
                        )
                    };
                self.change_pin(
                    key_agreement,
                    new_pin_enc.ok_or(ErrorStatus::MissingParameter)?,
                    pin_hash_enc.ok_or(ErrorStatus::MissingParameter)?,
                    pin_uv_auth_param.ok_or(ErrorStatus::MissingParameter)?,
                )
            }
            6 | 9 => {
                let (pin_hash_enc, permissions, rp_id) = if let Some(params) = map_map(&request, 4)
                {
                    (
                        map_bytes(params, 1),
                        map_integer(params, 2)
                            .and_then(|v| u8::try_from(v).ok())
                            .and_then(Ctap2PermissionFlags::from_bits),
                        map_text(params, 3).map(str::to_owned),
                    )
                } else {
                    (
                        map_bytes(&request, 6),
                        map_integer(&request, 9)
                            .and_then(|v| u8::try_from(v).ok())
                            .and_then(Ctap2PermissionFlags::from_bits),
                        map_text(&request, 10).map(str::to_owned),
                    )
                };
                self.get_pin_uv_auth_token(
                    key_agreement,
                    pin_hash_enc.ok_or(ErrorStatus::MissingParameter)?,
                    permissions.ok_or(ErrorStatus::MissingParameter)?,
                    rp_id,
                )
            }
            10 => {
                let (permissions, rp_id) = if let Some(params) = map_map(&request, 4) {
                    (
                        map_integer(params, 2)
                            .and_then(|v| u8::try_from(v).ok())
                            .and_then(Ctap2PermissionFlags::from_bits),
                        map_text(params, 3).map(str::to_owned),
                    )
                } else {
                    (
                        map_integer(&request, 9)
                            .and_then(|v| u8::try_from(v).ok())
                            .and_then(Ctap2PermissionFlags::from_bits),
                        map_text(&request, 10).map(str::to_owned),
                    )
                };
                self.get_pin_uv_auth_token_using_uv(
                    key_agreement,
                    permissions.ok_or(ErrorStatus::MissingParameter)?,
                    rp_id,
                )
            }
            _ => Err(ErrorStatus::InvalidCommand),
        }
    }

    fn credential_management(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        if !self.session.verify_matches_current() {
            return Err(ErrorStatus::OperationDenied);
        }
        let request = decode_map(body)?;
        let sub_command = map_integer(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        let params = map_map(&request, 2);
        let protocol = map_integer(&request, 3);
        let auth_param = map_bytes(&request, 4);
        let message = management_auth_message(sub_command, params);

        if self.client_pin.is_none() {
            return Err(ErrorStatus::PinNotSet);
        }
        self.validate_pin_uv_auth(
            protocol,
            auth_param,
            &message,
            Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
            None,
        )?;

        if self.management.as_ref().is_some_and(|state| {
            state.created_at.elapsed() > Duration::from_secs(30)
                || state.session_uid != self.session.uid
        }) {
            self.management = None;
        }

        match sub_command {
            1 => {
                let count = self
                    .credentials
                    .iter()
                    .filter(|credential| credential.discoverable)
                    .count();
                Ok(encode_response(
                    cbor!({
                        1 => count as u64,
                        2 => MAX_RESIDENT_CREDENTIALS.saturating_sub(count) as u64,
                    })
                    .unwrap(),
                ))
            }
            2 => self.enumerate_rps_begin(),
            3 => self.enumerate_rps_next(),
            4 => self.enumerate_credentials_begin(params),
            5 => self.enumerate_credentials_next(),
            6 => self.delete_credential(params),
            7 => self.update_user_information(params),
            _ => Err(ErrorStatus::InvalidCommand),
        }
    }

    fn enumerate_rps_begin(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        let mut rp_indexes: Vec<usize> = Vec::new();
        for (index, credential) in self.credentials.iter().enumerate() {
            if credential.discoverable
                && !rp_indexes
                    .iter()
                    .any(|existing| self.credentials[*existing].rp_id == credential.rp_id)
            {
                rp_indexes.push(index);
            }
        }
        let Some(&first) = rp_indexes.first() else {
            return Err(ErrorStatus::NoCredentials);
        };
        let total = rp_indexes.len();
        self.management = Some(ManagementState {
            rp_indexes,
            rp_position: 1,
            credential_indexes: Vec::new(),
            credential_position: 0,
            session_uid: self.session.uid,
            created_at: Instant::now(),
        });
        Ok(encode_rp_response(&self.credentials[first], Some(total)))
    }

    fn enumerate_rps_next(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        let state = self.management.as_mut().ok_or(ErrorStatus::NoCredentials)?;
        let index = *state
            .rp_indexes
            .get(state.rp_position)
            .ok_or(ErrorStatus::NoCredentials)?;
        state.rp_position += 1;
        Ok(encode_rp_response(&self.credentials[index], None))
    }

    fn enumerate_credentials_begin(
        &mut self,
        params: Option<&[(Value, Value)]>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let params = params.ok_or(ErrorStatus::MissingParameter)?;
        let rp_hash = map_bytes(params, 1).ok_or(ErrorStatus::MissingParameter)?;
        if rp_hash.len() != 32 {
            return Err(ErrorStatus::InvalidParameter);
        }
        let mut indexes = Vec::new();
        for (index, credential) in self.credentials.iter().enumerate() {
            if credential.discoverable
                && Sha256::digest(credential.rp_id.as_bytes()).as_slice() == rp_hash
            {
                indexes.push(index);
            }
        }
        let Some(&first) = indexes.first() else {
            return Err(ErrorStatus::NoCredentials);
        };
        let total = indexes.len();
        self.management = Some(ManagementState {
            rp_indexes: Vec::new(),
            rp_position: 0,
            credential_indexes: indexes,
            credential_position: 1,
            session_uid: self.session.uid,
            created_at: Instant::now(),
        });
        Ok(encode_credential_management_response(
            &self.credentials[first],
            Some(total),
        ))
    }

    fn enumerate_credentials_next(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        let state = self.management.as_mut().ok_or(ErrorStatus::NoCredentials)?;
        let index = *state
            .credential_indexes
            .get(state.credential_position)
            .ok_or(ErrorStatus::NoCredentials)?;
        state.credential_position += 1;
        Ok(encode_credential_management_response(
            &self.credentials[index],
            None,
        ))
    }

    fn delete_credential(
        &mut self,
        params: Option<&[(Value, Value)]>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let params = params.ok_or(ErrorStatus::MissingParameter)?;
        let descriptor = map_map(params, 2).ok_or(ErrorStatus::MissingParameter)?;
        let id = map_bytes(descriptor, "id").ok_or(ErrorStatus::MissingParameter)?;
        let index = self
            .credentials
            .iter()
            .position(|credential| credential.discoverable && credential.id == id)
            .ok_or(ErrorStatus::NoCredentials)?;
        store::delete_ctap2_credential_from_dir(&self.store_dir, id).map_err(|error| {
            log::warn!("failed to delete credential from store: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        self.credentials.remove(index);
        self.management = None;
        Ok(encode_response(Value::Map(Vec::new())))
    }

    fn update_user_information(
        &mut self,
        params: Option<&[(Value, Value)]>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let params = params.ok_or(ErrorStatus::MissingParameter)?;
        let descriptor = map_map(params, 2).ok_or(ErrorStatus::MissingParameter)?;
        let id = map_bytes(descriptor, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user = map_map(params, 3).ok_or(ErrorStatus::MissingParameter)?;
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.discoverable && credential.id == id)
            .ok_or(ErrorStatus::NoCredentials)?;
        if let Some(user_id) = map_bytes(user, "id") {
            credential.user_handle = user_id.to_vec();
        }
        credential.user_name = map_text(user, "name").map(str::to_owned);
        credential.user_display_name = map_text(user, "displayName").map(str::to_owned);
        self.save_credentials();
        self.management = None;
        Ok(encode_response(Value::Map(Vec::new())))
    }

    fn set_pin(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        new_pin_enc: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<Vec<u8>, ErrorStatus> {
        if self.client_pin.is_some() {
            return Err(ErrorStatus::InvalidCommand);
        }
        if new_pin_enc.len() < 16 || !(new_pin_enc.len() - 16).is_multiple_of(16) {
            return Err(ErrorStatus::InvalidParameter);
        }
        let (aes_key, hmac_key) = self.pin_uv_keys(key_agreement)?;
        verify_pin_uv_auth_param(&hmac_key, pin_uv_auth_param, new_pin_enc)?;
        let new_pin = decrypt_pin(&aes_key, new_pin_enc)?;
        validate_new_pin(&new_pin)?;

        let mut pin_salt = vec![0u8; 32];
        fill_random(&mut pin_salt);
        let pin_hash = Sha256::digest(&new_pin);
        let pin_verifier = pin_verifier(&pin_salt, &pin_hash[..16]);
        let state = ClientPinState {
            pin_salt,
            pin_verifier,
            retries: PIN_RETRIES,
        };
        self.persist_client_pin(&state)?;
        self.client_pin = Some(state);
        Ok(encode_response(Value::Map(Vec::new())))
    }

    fn change_pin(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        new_pin_enc: &[u8],
        pin_hash_enc: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<Vec<u8>, ErrorStatus> {
        if self.client_pin.is_none() {
            return Err(ErrorStatus::PinNotSet);
        }
        if new_pin_enc.len() < 16
            || !(new_pin_enc.len() - 16).is_multiple_of(16)
            || pin_hash_enc.len() < 16
            || !(pin_hash_enc.len() - 16).is_multiple_of(16)
        {
            return Err(ErrorStatus::InvalidParameter);
        }
        let (aes_key, hmac_key) = self.pin_uv_keys(key_agreement)?;
        let mut auth_message = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_message.extend_from_slice(new_pin_enc);
        auth_message.extend_from_slice(pin_hash_enc);
        verify_pin_uv_auth_param(&hmac_key, pin_uv_auth_param, &auth_message)?;
        let new_pin = decrypt_pin(&aes_key, new_pin_enc)?;
        validate_new_pin(&new_pin)?;
        let pin_hash = decrypt_pin_hash(&aes_key, pin_hash_enc)?;
        self.authenticate_pin(&pin_hash)?;

        let mut pin_salt = vec![0u8; 32];
        fill_random(&mut pin_salt);
        let state = ClientPinState {
            pin_salt: pin_salt.clone(),
            pin_verifier: {
                let pin_hash = Sha256::digest(&new_pin);
                pin_verifier(&pin_salt, &pin_hash[..16])
            },
            retries: PIN_RETRIES,
        };
        self.persist_client_pin(&state)?;
        self.client_pin = Some(state);
        Ok(encode_response(Value::Map(Vec::new())))
    }

    fn get_pin_uv_auth_token(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        pin_hash_enc: &[u8],
        permissions: Ctap2PermissionFlags,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        if permissions.is_empty() {
            return Err(ErrorStatus::InvalidParameter);
        }
        if permissions.contains(Ctap2PermissionFlags::GET_ASSERTION) && rp_id.is_none() {
            return Err(ErrorStatus::InvalidParameter);
        }
        let (aes_key, _mac_key) = self.pin_uv_keys(key_agreement)?;
        let pin_hash = decrypt_pin_hash(&aes_key, pin_hash_enc)?;
        self.authenticate_pin(&pin_hash)?;

        let mut token = vec![0u8; 32];
        fill_random(&mut token);
        self.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions,
            rp_id,
            issued_at: Instant::now(),
        });
        let encrypted_token = encrypt_aes(&aes_key, &token)?;
        let pin_uv_auth_param = compute_pin_uv_auth_param(&token, &encrypted_token)?;
        Ok(encode_response(
            cbor!({
                2 => Value::Bytes(encrypted_token),
                3 => Value::Bytes(pin_uv_auth_param),
            })
            .unwrap(),
        ))
    }

    fn get_pin_uv_auth_token_using_uv(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        permissions: Ctap2PermissionFlags,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        if permissions.is_empty() {
            return Err(ErrorStatus::InvalidParameter);
        }
        if permissions.contains(Ctap2PermissionFlags::GET_ASSERTION) && rp_id.is_none() {
            return Err(ErrorStatus::InvalidParameter);
        }
        if !self.session.verify_matches_current()
            || !approval::approve("Verify identity for a FIDO2 operation", &self.session)
            || !self.session.verify_matches_current()
        {
            return Err(ErrorStatus::OperationDenied);
        }
        let (aes_key, _mac_key) = self.pin_uv_keys(key_agreement)?;
        let mut token = vec![0u8; 32];
        fill_random(&mut token);
        self.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions,
            rp_id,
            issued_at: Instant::now(),
        });
        let encrypted_token = encrypt_aes(&aes_key, &token)?;
        let pin_uv_auth_param = compute_pin_uv_auth_param(&token, &encrypted_token)?;
        Ok(encode_response(
            cbor!({
                2 => Value::Bytes(encrypted_token),
                3 => Value::Bytes(pin_uv_auth_param),
            })
            .unwrap(),
        ))
    }

    fn pin_uv_keys(
        &self,
        key_agreement: Option<&[(Value, Value)]>,
    ) -> Result<([u8; 32], [u8; 32]), ErrorStatus> {
        let client_key = key_agreement.ok_or(ErrorStatus::MissingParameter)?;
        let client_key = parse_key_agreement(client_key)?;
        let secret = self
            .key_agreement
            .as_ref()
            .ok_or(ErrorStatus::InvalidCommand)?
            .diffie_hellman(&client_key);
        derive_protocol2_keys(secret.raw_secret_bytes().as_slice())
            .map_err(|_| ErrorStatus::OperationDenied)
    }

    fn authenticate_pin(&mut self, pin_hash: &[u8]) -> Result<(), ErrorStatus> {
        if pin_hash.len() != 16 {
            return Err(ErrorStatus::InvalidParameter);
        }
        let Some(pin) = self.client_pin.as_mut() else {
            return Err(ErrorStatus::PinNotSet);
        };
        if pin.retries == 0 {
            return Err(ErrorStatus::PinBlocked);
        }

        let candidate = pin_verifier(&pin.pin_salt, pin_hash);
        if !constant_time_equal(&candidate, &pin.pin_verifier) {
            pin.retries = pin.retries.saturating_sub(1);
            let retries = pin.retries;
            let state = pin.clone();
            self.persist_client_pin(&state)?;
            return Err(if retries == 0 {
                ErrorStatus::PinBlocked
            } else {
                ErrorStatus::PinInvalid
            });
        }

        if pin.retries != PIN_RETRIES {
            pin.retries = PIN_RETRIES;
            let state = pin.clone();
            self.persist_client_pin(&state)?;
        }
        Ok(())
    }

    fn persist_client_pin(&self, state: &ClientPinState) -> Result<(), ErrorStatus> {
        store::save_client_pin_state_to_dir(
            &self.store_dir,
            &store::StoredClientPinState {
                pin_salt: state.pin_salt.clone(),
                pin_verifier: state.pin_verifier.clone(),
                retries: state.retries,
                integrity_mac: None,
            },
        )
        .map_err(|error| {
            log::warn!("failed to persist clientPIN state: {error:?}");
            ErrorStatus::OperationDenied
        })
    }

    fn save_credentials(&self) {
        let credentials: Vec<_> = self
            .credentials
            .iter()
            .map(|credential| store::StoredCtap2Credential {
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
            })
            .collect();

        let path = store::credentials_database_path_in_dir(&self.store_dir);
        if let Err(error) = store::save_ctap2_credentials_to_dir(&self.store_dir, &credentials) {
            log::warn!("failed to save CTAP2 credential store: {error:?}");
        } else {
            log::info!(
                "saved {} TPM-backed CTAP2 credentials to SQLite store {}",
                credentials.len(),
                path.display()
            );
        }
    }

    fn ensure_tpm(&mut self) -> Option<&mut tpm::Tpm> {
        if self.tpm.is_none() {
            let path = self.tpm_path.clone()?;
            let pcr_indices = store::load_default_pcr_policy(&self.store_dir).unwrap_or(None);

            for attempt in 0..100 {
                match tpm::Tpm::open(&path, pcr_indices.as_deref()) {
                    Ok(tpm) => {
                        log::info!(
                            "TPM opened with PCR policy {:?}",
                            pcr_indices.as_deref().unwrap_or(&[7])
                        );
                        self.tpm = Some(tpm);
                        break;
                    }
                    Err(error) if attempt < 99 => {
                        log::debug!(
                            "retrying TPM open for CTAP2 credentials at {}: {error:?}",
                            path.display()
                        );
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        log::warn!(
                            "failed to open TPM for CTAP2 credentials at {}: {error:?}",
                            path.display()
                        );
                        return None;
                    }
                }
            }
        }

        self.tpm.as_mut()
    }

    fn assertion_approved(&mut self, rp_id: &str) -> bool {
        if !self.session.verify_matches_current() {
            log::error!("session changed before assertion approval for {rp_id}");
            return false;
        }

        if !approval::approve(
            &format!("Authenticate with passkey for {rp_id}"),
            &self.session,
        ) {
            return false;
        }

        if !self.session.verify_matches_current() {
            log::error!("session changed during assertion approval for {rp_id}");
            return false;
        }

        true
    }

    fn validate_pin_uv_auth(
        &mut self,
        protocol: Option<i128>,
        auth_param: Option<&[u8]>,
        message: &[u8],
        permission: Ctap2PermissionFlags,
        rp_id: Option<&str>,
    ) -> Result<bool, ErrorStatus> {
        if !self.session.verify_matches_current() {
            return Err(ErrorStatus::OperationDenied);
        }
        if protocol.is_none() && auth_param.is_none() {
            return Ok(false);
        }
        validate_pin_uv_protocol(protocol)?;
        let auth_param = auth_param.ok_or(ErrorStatus::MissingParameter)?;
        let Some(token) = self
            .pin_uv_auth_token
            .as_ref()
            .filter(|token| token.issued_at.elapsed() <= Duration::from_secs(600))
            .cloned()
        else {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        };
        if !token.permissions.contains(permission)
            || token
                .rp_id
                .as_deref()
                .is_some_and(|token_rp_id| Some(token_rp_id) != rp_id)
        {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        }
        if auth_param.len() != 16 && auth_param.len() != 32 {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        }
        let mut mac =
            HmacSha256::new_from_slice(&token.value).map_err(|_| ErrorStatus::OperationDenied)?;
        mac.update(message);
        let expected = mac.finalize().into_bytes();
        if constant_time_equal(&expected[..auth_param.len()], auth_param) {
            Ok(true)
        } else {
            self.pin_uv_auth_token = None;
            Err(ErrorStatus::PinAuthInvalid)
        }
    }

    /// Execute a TPM command issued by the management thread.
    /// This runs on the main daemon thread which owns the TPM context.
    pub fn handle_tpm_command(&mut self, command: TpmCommand) -> color_eyre::Result<()> {
        match command {
            TpmCommand::PcrPolicyUpdate(cmd) => {
                let tpm = self
                    .ensure_tpm()
                    .ok_or_else(|| color_eyre::eyre::eyre!("TPM not available"))?;
                tpm.set_pcr_indices(&cmd.pcr_indices)
                    .wrap_err("selecting PCRs for policy update")?;
                let new_policy = tpm
                    .update_authorized_policy(&cmd.authority, &cmd.authority_name, &cmd.policy_ref)
                    .wrap_err("updating PCR policy via management TPM command")?;
                let stored_policy = store::StoredPcrPolicy {
                    selection: new_policy.selection,
                    digest: new_policy.digest,
                    policy_ref: new_policy.policy_ref,
                    authority_name: new_policy.authority_name,
                    authority_signature: new_policy.authority_signature,
                    policy_version: store::StoredPcrPolicy::current_version(),
                };
                store::update_ctap2_policy_in_dir(
                    &self.store_dir,
                    &cmd.credential_id,
                    &stored_policy,
                )
                .wrap_err("saving PCR policy after TPM command")?;
                log::info!(
                    "updated PCR policy for credential {}",
                    hex::encode(&cmd.credential_id)
                );
                Ok(())
            }
            TpmCommand::PassphraseChange(cmd) => {
                let tpm = self
                    .ensure_tpm()
                    .ok_or_else(|| color_eyre::eyre::eyre!("TPM not available"))?;
                let updated_key = tpm
                    .change_key_auth(&cmd.recovery_key, &cmd.new_passphrase_hash)
                    .wrap_err("changing TPM recovery key authorization")?;
                store::update_recovery_slot_in_dir(
                    &self.store_dir,
                    &cmd.credential_id,
                    &updated_key.private,
                    &cmd.new_salt,
                    &cmd.new_passphrase_hash,
                    &cmd.new_kdf,
                )
                .wrap_err("saving updated recovery slot after TPM command")?;
                log::info!(
                    "changed recovery passphrase for credential {}",
                    hex::encode(&cmd.credential_id)
                );
                Ok(())
            }
            TpmCommand::PcrDigestCheck(cmd) => {
                let selection = tpm::pcr_selection_for_indices(&cmd.pcr_indices)
                    .wrap_err("building PCR selection from indices")?;
                let tpm = self
                    .ensure_tpm()
                    .ok_or_else(|| color_eyre::eyre::eyre!("TPM not available"))?;
                let digest = tpm
                    .current_pcr_digest(&selection)
                    .wrap_err("reading current PCR digest")?;
                let _ = cmd.resp_tx.send(Ok(digest));
                Ok(())
            }
        }
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new(store::dev_store_dir(), None)
    }
}

/// A TPM-bound operation requested by the management thread.
pub enum TpmCommand {
    PcrPolicyUpdate(PcrPolicyUpdateCommand),
    PassphraseChange(PassphraseChangeCommand),
    PcrDigestCheck(PcrDigestCheckCommand),
}

/// Data needed to update a credential's PCR policy via `policy_authorize`.
pub struct PcrPolicyUpdateCommand {
    pub credential_id: Vec<u8>,
    pub pcr_indices: Vec<u32>,
    pub authority: tpm::TpmCredential,
    pub authority_name: Vec<u8>,
    pub policy_ref: Vec<u8>,
}

/// Data needed to change a credential's recovery passphrase via `change_key_auth`.
pub struct PassphraseChangeCommand {
    pub credential_id: Vec<u8>,
    pub recovery_key: tpm::TpmCredential,
    pub new_passphrase_hash: Vec<u8>,
    pub new_salt: Vec<u8>,
    pub new_kdf: tpm::RecoveryKdf,
}

/// Data needed to check the current PCR digest for a given selection.
pub struct PcrDigestCheckCommand {
    pub pcr_indices: Vec<u32>,
    pub resp_tx: mpsc::Sender<color_eyre::Result<Vec<u8>>>,
}

/// Result type for a TPM command sent across threads.
pub type TpmCmdResult = std::result::Result<(), String>;

/// Channel sender for dispatching TPM commands from the management thread
/// to the main daemon thread.  Each command carries a one-shot reply channel.
pub type TpmCmdSender = mpsc::Sender<(TpmCommand, mpsc::Sender<TpmCmdResult>)>;

pub fn command_name(command: Ctap2Command) -> &'static str {
    match command {
        Ctap2Command::MakeCredential => "authenticatorMakeCredential",
        Ctap2Command::GetAssertion => "authenticatorGetAssertion",
        Ctap2Command::GetNextAssertion => "authenticatorGetNextAssertion",
        Ctap2Command::GetInfo => "authenticatorGetInfo",
        Ctap2Command::ClientPin => "authenticatorClientPIN",
        Ctap2Command::CredentialManagement | Ctap2Command::CredentialManagementPreview => {
            "authenticatorCredentialManagement"
        }
        Ctap2Command::Reset => "authenticatorReset",
        Ctap2Command::Selection => "authenticatorSelection",
        Ctap2Command::BioEnrollment | Ctap2Command::BioEnrollmentPreview => {
            "authenticatorBioEnrollment"
        }
        Ctap2Command::LargeBlobs => "authenticatorLargeBlobs",
        Ctap2Command::Config => "authenticatorConfig",
    }
}

fn get_info_response(client_pin: bool) -> Vec<u8> {
    encode_response(
        cbor!({
            1 => ["FIDO_2_1", "FIDO_2_0"],
            2 => ["credProps"],
            3 => Value::Bytes(AAGUID.to_vec()),
            4 => {
                "plat" => false,
                "rk" => true,
                "up" => true,
                // The polkit approval prompt is this authenticator's user
                // verification method; authenticatorSelection is the CTAP2.1
                // UV gesture. Advertise `uv` so browsers route UV through it.
                "uv" => true,
                "clientPin" => client_pin,
                // CTAP 2.2 §6.4 requires pinUvAuthToken when either clientPin
                // or built-in UV is available. Polkit-backed UV is available
                // even before a client PIN has been configured.
                "pinUvAuthToken" => true,
                "credMgmt" => true,
                "makeCredUvNotRqd" => true,
            },
            6 => [PIN_UV_AUTH_PROTOCOL],
            5 => 1200,
            9 => ["usb"],
            10 => [{"type" => "public-key", "alg" => COSE_ALG_ES256}],
        })
        .unwrap(),
    )
}

fn decode_map(body: &[u8]) -> Result<Vec<(Value, Value)>, ErrorStatus> {
    match ciborium::from_reader::<Value, _>(body) {
        Ok(Value::Map(map)) => Ok(map),
        Ok(_) | Err(_) => Err(ErrorStatus::InvalidCbor),
    }
}

trait MapKey {
    fn matches(&self, value: &Value) -> bool;
}

impl MapKey for i128 {
    fn matches(&self, value: &Value) -> bool {
        value.as_integer().map(i128::from) == Some(*self)
    }
}

impl MapKey for &str {
    fn matches(&self, value: &Value) -> bool {
        value.as_text() == Some(*self)
    }
}

fn map_value<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&Value> {
    map.iter()
        .find_map(|(candidate, value)| key.matches(candidate).then_some(value))
}

fn map_bytes<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[u8]> {
    map_value(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
}

fn map_integer<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<i128> {
    map_value(map, key)
        .and_then(Value::as_integer)
        .map(i128::from)
}

fn map_text<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&str> {
    map_value(map, key).and_then(Value::as_text)
}

fn map_bool<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<bool> {
    map_value(map, key).and_then(Value::as_bool)
}

fn map_array<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[Value]> {
    map_value(map, key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn map_map<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[(Value, Value)]> {
    map_value(map, key)
        .and_then(Value::as_map)
        .map(Vec::as_slice)
}

fn validate_pin_uv_protocol(protocol: Option<i128>) -> Result<(), ErrorStatus> {
    match protocol.and_then(|value| u64::try_from(value).ok()) {
        Some(PIN_UV_AUTH_PROTOCOL) => Ok(()),
        Some(_) => Err(ErrorStatus::InvalidParameter),
        None => Err(ErrorStatus::MissingParameter),
    }
}

fn key_agreement_response(secret: &EphemeralSecret) -> Vec<u8> {
    let public_key = secret.public_key().to_sec1_bytes();
    encode_response(cbor!({
        1 => cose_key_agreement_coordinates(public_key[1..33].to_vec(), public_key[33..65].to_vec()),
    }).unwrap())
}

fn parse_key_agreement(map: &[(Value, Value)]) -> Result<PublicKey, ErrorStatus> {
    let kty = map_integer(map, 1).ok_or(ErrorStatus::InvalidParameter)?;
    let alg = map_integer(map, 3).ok_or(ErrorStatus::InvalidParameter)?;
    let crv = map_integer(map, -1).ok_or(ErrorStatus::InvalidParameter)?;
    let x = map_bytes(map, -2).ok_or(ErrorStatus::InvalidParameter)?;
    let y = map_bytes(map, -3).ok_or(ErrorStatus::InvalidParameter)?;
    if kty != 2 || alg != -25 || crv != 1 || x.len() != 32 || y.len() != 32 {
        return Err(ErrorStatus::InvalidParameter);
    }

    let mut encoded = Vec::with_capacity(65);
    encoded.push(0x04);
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&encoded).map_err(|_| ErrorStatus::InvalidParameter)
}

fn derive_protocol2_keys(shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32]), ()> {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_secret);
    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];
    hkdf.expand(b"CTAP2 AES key", &mut aes_key)
        .map_err(|_| ())?;
    hkdf.expand(b"CTAP2 HMAC key", &mut hmac_key)
        .map_err(|_| ())?;
    Ok((aes_key, hmac_key))
}

fn verify_pin_uv_auth_param(
    hmac_key: &[u8; 32],
    auth_param: &[u8],
    message: &[u8],
) -> Result<(), ErrorStatus> {
    if auth_param.len() != 16 && auth_param.len() != 32 {
        return Err(ErrorStatus::PinAuthInvalid);
    }
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| ErrorStatus::OperationDenied)?;
    mac.update(message);
    let expected = mac.finalize().into_bytes();
    constant_time_equal(&expected[..auth_param.len()], auth_param)
        .then_some(())
        .ok_or(ErrorStatus::PinAuthInvalid)
}

/// Compute `pinUvAuthParam` (response key 3) for a `getPinUvAuthToken`
/// response. Per CTAP 2.2 §6.5.5.7, this is
/// HMAC-SHA256(token, encryptedToken), where `token` is the issued
/// pinUvAuthToken (used as the MAC key). For PIN/UV Auth Protocol 2 the
/// full 32-byte digest is returned (libfido2 `cbor_encode_pin_auth`).
/// This mirrors `verify_pin_uv_auth_param` on the client side.
fn compute_pin_uv_auth_param(token: &[u8], message: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    let mut mac = HmacSha256::new_from_slice(token).map_err(|_| ErrorStatus::OperationDenied)?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    Ok(result.to_vec())
}

fn encrypt_aes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
        return Err(ErrorStatus::InvalidParameter);
    }
    let mut iv = [0u8; 16];
    fill_random(&mut iv);
    let mut encrypted = plaintext.to_vec();
    let length = encrypted.len();
    Aes256CbcEncryptor::new(key.into(), (&iv).into())
        .encrypt_padded::<NoPadding>(&mut encrypted, length)
        .map_err(|_| ErrorStatus::OperationDenied)?;
    let mut result = iv.to_vec();
    result.extend(encrypted);
    Ok(result)
}

fn decrypt_aes(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(16) {
        return Err(ErrorStatus::InvalidParameter);
    }
    let iv: &[u8; 16] = ciphertext[..16]
        .try_into()
        .map_err(|_| ErrorStatus::InvalidParameter)?;
    let data = &ciphertext[16..];
    let mut decrypted = data.to_vec();
    let plaintext = Aes256CbcDecryptor::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut decrypted)
        .map_err(|_| ErrorStatus::OperationDenied)?;
    Ok(plaintext.to_vec())
}

fn decrypt_pin(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    let decrypted = decrypt_aes(key, encrypted)?;
    let Some(first_zero) = decrypted.iter().position(|byte| *byte == 0) else {
        return Ok(decrypted);
    };
    if decrypted[first_zero..].iter().any(|byte| *byte != 0) {
        return Err(ErrorStatus::PinPolicyViolation);
    }
    Ok(decrypted[..first_zero].to_vec())
}

fn decrypt_pin_hash(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    let decrypted = decrypt_aes(key, encrypted)?;
    if decrypted.len() != 16 {
        return Err(ErrorStatus::InvalidParameter);
    }
    Ok(decrypted)
}

fn validate_new_pin(pin: &[u8]) -> Result<(), ErrorStatus> {
    if !(4..=63).contains(&pin.len()) || pin.contains(&0) {
        return Err(ErrorStatus::PinPolicyViolation);
    }
    Ok(())
}

fn pin_verifier(salt: &[u8], pin_hash: &[u8]) -> Vec<u8> {
    let mut verifier = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(pin_hash, salt, PIN_KDF_ROUNDS, &mut verifier);
    verifier
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn supports_es256(value: &Value) -> bool {
    let Value::Map(map) = value else {
        return false;
    };
    map_text(map, "type") == Some("public-key")
        && map_value(map, "alg")
            .and_then(Value::as_integer)
            .and_then(|integer| i64::try_from(integer).ok())
            == Some(COSE_ALG_ES256)
}

fn validate_make_credential_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    validate_common_options(options, false)?;
    validate_resident_key_options(options)?;
    Ok(())
}

fn validate_get_assertion_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    validate_common_options(options, false)
}

fn validate_credential_descriptor_list(list: Option<&[Value]>) -> Result<(), ErrorStatus> {
    let Some(list) = list else {
        return Ok(());
    };

    for entry in list {
        let Value::Map(map) = entry else {
            return Err(ErrorStatus::InvalidCbor);
        };
        if map_text(map, "type") != Some("public-key") {
            return Err(ErrorStatus::InvalidCbor);
        }
        if map_bytes(map, "id").is_none() {
            return Err(ErrorStatus::InvalidCbor);
        }
    }

    Ok(())
}

fn validate_common_options(
    options: Option<&[(Value, Value)]>,
    reject_user_presence_false: bool,
) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };

    if map_bool(options, "uv") == Some(true) {
        log::info!("request requires user verification; continuing with local approval flow");
    }
    if map_bool(options, "up") == Some(false) {
        log::info!("request disables user presence");
        if reject_user_presence_false && map_bool(options, "uv") != Some(true) {
            log::info!(
                "request disables user presence without user verification, which is not supported"
            );
            return Err(ErrorStatus::UnsupportedOption);
        }
    }

    Ok(())
}

fn validate_resident_key_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };

    if let Some(require_resident_key) = map_bool(options, "requireResidentKey") {
        log::info!("request sets requireResidentKey={require_resident_key}");
    }

    if let Some(resident_key) = map_text(options, "residentKey") {
        match resident_key {
            "discouraged" | "preferred" | "required" => {
                log::info!("request sets residentKey={resident_key}");
            }
            _ => return Err(ErrorStatus::InvalidCbor),
        }
    }

    Ok(())
}

fn validate_attestation_conveyance(attestation: Option<&str>) -> Result<(), ErrorStatus> {
    let Some(attestation) = attestation else {
        return Ok(());
    };

    match attestation {
        "none" | "indirect" | "direct" | "enterprise" => {
            log::info!("request sets attestation={attestation}");
            Ok(())
        }
        _ => Err(ErrorStatus::InvalidCbor),
    }
}

fn excluded_credential_exists(
    credentials: &[Credential],
    rp_id: &str,
    exclude_list: Option<&[Value]>,
) -> bool {
    let Some(exclude_list) = exclude_list else {
        return false;
    };

    credentials.iter().any(|credential| {
        credential.rp_id == rp_id
            && credential_descriptor_list_contains(exclude_list, &credential.id)
    })
}

fn allow_list_allows(allow_list: Option<&[Value]>, credential_id: &[u8]) -> bool {
    let Some(allow_list) = allow_list else {
        return true;
    };

    if allow_list.is_empty() {
        return true;
    }

    credential_descriptor_list_contains(allow_list, credential_id)
}

fn validate_client_data_hash(client_data_hash: &[u8]) -> Result<(), ErrorStatus> {
    if client_data_hash.len() != 32 {
        log::info!(
            "request provided invalid clientDataHash length {}; expected 32 bytes",
            client_data_hash.len()
        );
        return Err(ErrorStatus::InvalidCbor);
    }

    Ok(())
}

fn matching_credential_indexes(
    credentials: &[Credential],
    rp_id: &str,
    allow_list: Option<&[Value]>,
) -> Vec<usize> {
    credentials
        .iter()
        .enumerate()
        .filter_map(|(index, credential)| {
            if credential.rp_id != rp_id {
                return None;
            }
            let matches = match allow_list {
                Some(list) if !list.is_empty() => allow_list_allows(Some(list), &credential.id),
                _ => credential.discoverable,
            };
            matches.then_some(index)
        })
        .collect()
}

fn credential_descriptor_list_contains(list: &[Value], credential_id: &[u8]) -> bool {
    list.iter().any(|entry| {
        let Value::Map(map) = entry else {
            return false;
        };
        map_text(map, "type") == Some("public-key") && map_bytes(map, "id") == Some(credential_id)
    })
}

fn make_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<(&[u8], &Value)>,
    extensions: Option<&Value>,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(flags | if extensions.is_some() { 0x80 } else { 0x00 });
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((credential_id, public_key)) = attested_credential_data {
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        ciborium::into_writer(public_key, &mut auth_data).expect("serializing static COSE key");
    }

    if let Some(extensions) = extensions {
        ciborium::into_writer(extensions, &mut auth_data).expect("serializing CTAP2 extensions");
    }

    auth_data
}

fn cred_props_extension(discoverable: bool) -> Value {
    Value::Map(vec![(
        Value::Text("credProps".to_owned()),
        Value::Map(vec![(
            Value::Text("rk".to_owned()),
            Value::Bool(discoverable),
        )]),
    )])
}

fn display_rp_label(rp_name: Option<&str>, rp_id: &str) -> String {
    match rp_name {
        Some(name) if name != rp_id => format!("{name} ({rp_id})"),
        _ => rp_id.to_owned(),
    }
}

fn encode_rp_response(credential: &Credential, total: Option<usize>) -> Vec<u8> {
    let mut rp = vec![(
        Value::Text("id".to_owned()),
        Value::Text(credential.rp_id.clone()),
    )];
    rp.push((
        Value::Text("name".to_owned()),
        Value::Text(credential.rp_id.clone()),
    ));
    let mut response = vec![
        (Value::Integer(1.into()), Value::Map(rp)),
        (
            Value::Integer(2.into()),
            Value::Bytes(Sha256::digest(credential.rp_id.as_bytes()).to_vec()),
        ),
    ];
    if let Some(total) = total {
        response.push((
            Value::Integer(3.into()),
            Value::Integer((total as u64).into()),
        ));
    }
    encode_response(Value::Map(response))
}

fn encode_credential_management_response(credential: &Credential, total: Option<usize>) -> Vec<u8> {
    let mut user = vec![(
        Value::Text("id".to_owned()),
        Value::Bytes(credential.user_handle.clone()),
    )];
    if let Some(name) = &credential.user_name {
        user.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
    }
    if let Some(display_name) = &credential.user_display_name {
        user.push((
            Value::Text("displayName".to_owned()),
            Value::Text(display_name.clone()),
        ));
    }
    let mut response = vec![
        (Value::Integer(1.into()), Value::Map(user)),
        (
            Value::Integer(2.into()),
            Value::Map(vec![
                (
                    Value::Text("type".to_owned()),
                    Value::Text("public-key".to_owned()),
                ),
                (
                    Value::Text("id".to_owned()),
                    Value::Bytes(credential.id.clone()),
                ),
            ]),
        ),
        (
            Value::Integer(3.into()),
            cose_credential_public_key(&credential.key),
        ),
    ];
    if let Some(total) = total {
        response.push((
            Value::Integer(4.into()),
            Value::Integer((total as u64).into()),
        ));
    }
    encode_response(Value::Map(response))
}

fn encode_assertion_response(
    credential_id: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    user: Vec<(Value, Value)>,
    total_credentials: usize,
) -> Vec<u8> {
    let mut response = vec![
        (
            Value::Integer(1.into()),
            Value::Map(vec![
                (
                    Value::Text("type".to_owned()),
                    Value::Text("public-key".to_owned()),
                ),
                (Value::Text("id".to_owned()), Value::Bytes(credential_id)),
            ]),
        ),
        (Value::Integer(2.into()), Value::Bytes(auth_data)),
        (Value::Integer(3.into()), Value::Bytes(signature)),
        (Value::Integer(4.into()), Value::Map(user)),
    ];

    if total_credentials > 1 {
        response.push((
            Value::Integer(5.into()),
            Value::Integer((total_credentials as u64).into()),
        ));
    }

    encode_response(Value::Map(response))
}

fn cose_credential_public_key(key: &tpm::TpmCredential) -> Value {
    cose_public_key_coordinates(key.public_key_x.clone(), key.public_key_y.clone())
}

fn cose_public_key_coordinates(x: Vec<u8>, y: Vec<u8>) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (
            Value::Integer(3.into()),
            Value::Integer(COSE_ALG_ES256.into()),
        ),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ])
}

fn cose_key_agreement_coordinates(x: Vec<u8>, y: Vec<u8>) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-25).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ])
}

fn sign_credential(
    authenticator: &mut Authenticator,
    key: &tpm::TpmCredential,
    policy: Option<&store::StoredPcrPolicy>,
    authority: Option<&store::StoredRecoverySlot>,
    signed_data: &[u8],
) -> color_eyre::Result<Vec<u8>> {
    if let Some(policy) = policy
        && !store::StoredPcrPolicy::is_version_supported(policy.policy_version)
    {
        return Err(color_eyre::eyre::eyre!(
            "unsupported policy version {}",
            policy.policy_version
        ));
    }
    let pcr_indices = policy
        .map(|policy| tpm::pcr_indices_from_selection(&policy.selection))
        .transpose()
        .wrap_err("parsing stored PCR selection")?;
    let Some(tpm) = authenticator.ensure_tpm() else {
        #[cfg(test)]
        {
            return Ok(vec![0x5a; 64]);
        }
        #[cfg(not(test))]
        {
            return Err(color_eyre::eyre::eyre!(
                "TPM credential requires TPM context"
            ));
        }
    };
    if let Some(indices) = &pcr_indices {
        tpm.set_pcr_indices(indices)
            .wrap_err("selecting credential PCRs")?;
    }
    let digest = Sha256::digest(signed_data);
    let policy_binding = policy.map(|policy| tpm::PcrPolicyBinding {
        selection: policy.selection.clone(),
        digest: policy.digest.clone(),
        policy_ref: policy.policy_ref.clone(),
        authority_name: policy.authority_name.clone(),
        authority_signature: policy.authority_signature.clone(),
    });
    let authority_key = authority.map(|authority| tpm::TpmCredential {
        private: authority.key.private.clone(),
        public: authority.key.public.clone(),
        public_key_x: authority.key.public_key_x.clone(),
        public_key_y: authority.key.public_key_y.clone(),
        auth_value: authority.key.auth_value.clone(),
    });
    tpm.sign_digest_with_policy(
        key,
        policy_binding.as_ref(),
        authority_key.as_ref(),
        &digest,
    )
}

fn fill_random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("kernel random source available");
}

fn encode_response(response: Value) -> Vec<u8> {
    let mut payload = vec![0x00];
    let response = canonicalize_value(response);
    ciborium::into_writer(&response, &mut payload).expect("serializing CTAP2 response");
    payload
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Map(entries) => {
            let mut entries: Vec<_> = entries
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                canonical_key_bytes(left_key).cmp(&canonical_key_bytes(right_key))
            });
            Value::Map(entries)
        }
        other => other,
    }
}

fn canonical_key_bytes(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("serializing CTAP2 map key");
    encoded
}

fn management_auth_message(sub_command: i128, params: Option<&[(Value, Value)]>) -> Vec<u8> {
    let mut encoded = vec![sub_command as u8];
    if let Some(params) = params {
        let value = canonicalize_value(Value::Map(params.to_vec()));
        ciborium::into_writer(&value, &mut encoded).expect("serializing management parameters");
    }
    encoded
}

fn error_response(status: ErrorStatus) -> Vec<u8> {
    vec![status.into()]
}

pub fn update_pcr_policy_for_credential(
    store_dir: &std::path::Path,
    tpm_path: Option<&std::path::Path>,
    credential_id: &[u8],
    recovery_passphrase: &str,
    pcr_indices: &[u32],
) -> color_eyre::Result<()> {
    let credentials = store::load_ctap2_credentials_from_dir(store_dir, None)?;
    let credential = credentials
        .iter()
        .find(|c| c.id == credential_id)
        .ok_or_else(|| color_eyre::eyre::eyre!("credential not found"))?;
    let policy = credential
        .policy
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("credential has no PCR policy"))?;
    let recovery = credential
        .recovery
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("credential has no recovery slot"))?;
    let policy_ref = policy
        .policy_ref
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("credential has no policyRef"))?;
    let authority_name = policy
        .authority_name
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("credential has no authority name"))?;

    let mut passphrase_hash = tpm::recovery_passphrase_hash(
        &recovery.kdf,
        &recovery.passphrase_salt,
        recovery_passphrase,
    )?;
    let passphrase_ok = passphrase_hash == recovery.passphrase_hash;
    passphrase_hash.zeroize();
    if !passphrase_ok {
        color_eyre::eyre::bail!("recovery passphrase does not match");
    }

    let tpm_path = tpm_path.unwrap_or(std::path::Path::new("/dev/tpmrm0"));
    let mut tpm = tpm::Tpm::open(tpm_path, Some(pcr_indices))
        .wrap_err("opening TPM for PCR policy update")?;

    let authority = tpm::TpmCredential {
        private: recovery.key.private.clone(),
        public: recovery.key.public.clone(),
        public_key_x: recovery.key.public_key_x.clone(),
        public_key_y: recovery.key.public_key_y.clone(),
        auth_value: recovery.key.auth_value.clone(),
    };

    let new_policy = tpm
        .update_authorized_policy(&authority, authority_name, policy_ref)
        .wrap_err("updating authorized PCR policy")?;

    let stored_policy = store::StoredPcrPolicy {
        selection: new_policy.selection,
        digest: new_policy.digest,
        policy_ref: new_policy.policy_ref,
        authority_name: new_policy.authority_name,
        authority_signature: new_policy.authority_signature,
        policy_version: store::StoredPcrPolicy::current_version(),
    };

    println!(
        "credential={} old_policy={}={} proposed_policy={}={}",
        hex::encode(credential_id),
        policy.selection,
        hex::encode(&policy.digest),
        stored_policy.selection,
        hex::encode(&stored_policy.digest),
    );

    store::update_ctap2_policy_in_dir(store_dir, credential_id, &stored_policy)
        .wrap_err("saving updated PCR policy")?;

    log::info!(
        "updated PCR policy for credential {}",
        hex::encode(credential_id)
    );
    Ok(())
}

pub fn change_recovery_passphrase(
    store_dir: &std::path::Path,
    tpm_path: Option<&std::path::Path>,
    credential_id: &[u8],
    old_passphrase: &str,
    new_passphrase: &str,
) -> color_eyre::Result<()> {
    let credentials = store::load_ctap2_credentials_from_dir(store_dir, None)?;
    let credential = credentials
        .iter()
        .find(|c| c.id == credential_id)
        .ok_or_else(|| color_eyre::eyre::eyre!("credential not found"))?;
    let recovery = credential
        .recovery
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("credential has no recovery slot"))?;

    let mut old_hash =
        tpm::recovery_passphrase_hash(&recovery.kdf, &recovery.passphrase_salt, old_passphrase)?;
    if old_hash != recovery.passphrase_hash {
        old_hash.zeroize();
        color_eyre::eyre::bail!("recovery passphrase does not match");
    }
    old_hash.zeroize();

    let mut new_salt = vec![0u8; 32];
    getrandom::fill(&mut new_salt).wrap_err("generating new recovery passphrase salt")?;
    let new_kdf = tpm::RecoveryKdf::argon2id_default();
    let new_hash = tpm::recovery_passphrase_hash(&new_kdf, &new_salt, new_passphrase)?;

    let tpm_path = tpm_path.unwrap_or(std::path::Path::new("/dev/tpmrm0"));
    let pcr_indices = store::load_default_pcr_policy(store_dir).unwrap_or(None);
    let mut tpm = tpm::Tpm::open(tpm_path, pcr_indices.as_deref())
        .wrap_err("opening TPM for passphrase change")?;

    let recovery_key = tpm::TpmCredential {
        private: recovery.key.private.clone(),
        public: recovery.key.public.clone(),
        public_key_x: recovery.key.public_key_x.clone(),
        public_key_y: recovery.key.public_key_y.clone(),
        auth_value: recovery.key.auth_value.clone(),
    };
    let updated_key = tpm
        .change_key_auth(&recovery_key, &new_hash)
        .wrap_err("changing TPM recovery key authorization")?;

    store::update_recovery_slot_in_dir(
        store_dir,
        credential_id,
        &updated_key.private,
        &new_salt,
        &new_hash,
        &new_kdf,
    )
    .wrap_err("saving updated recovery slot")?;

    new_salt.zeroize();
    log::info!(
        "changed recovery passphrase for credential {}",
        hex::encode(credential_id)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    #[test]
    fn get_info_starts_with_success() {
        let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
        assert_eq!(response[0], 0x00);
        assert!(response.len() > 1);
    }

    #[test]
    fn get_info_uses_project_aaguid_and_algorithm_metadata() {
        let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected getInfo map");
        };

        assert_eq!(map_bytes(&map, 3), Some(AAGUID.as_slice()));
        assert!(
            map_value(&map, 9).is_some(),
            "transports key should be present"
        );
        assert!(
            map_value(&map, 10).is_some(),
            "algorithms key should be present"
        );
        assert_eq!(
            map_value(&map, 6),
            Some(&Value::Array(vec![Value::Integer(2.into())]))
        );
        assert_eq!(
            map_value(&map, 2),
            Some(&Value::Array(vec![Value::Text("credProps".to_owned())]))
        );
    }

    #[test]
    fn get_info_advertises_a_consistent_ctap21_configuration() {
        let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected getInfo map");
        };

        let versions = map_value(&map, 1)
            .and_then(Value::as_array)
            .expect("versions");
        assert!(versions.contains(&Value::Text("FIDO_2_0".to_owned())));
        assert!(versions.contains(&Value::Text("FIDO_2_1".to_owned())));
        assert_eq!(map_bytes(&map, 3).map(<[u8]>::len), Some(16));
        assert!(
            map_value(&map, 5)
                .and_then(Value::as_integer)
                .map(i128::from)
                .is_some_and(|size| size >= 1024),
            "maxMsgSize must accommodate the CTAP minimum message size"
        );

        let options = map_value(&map, 4).and_then(Value::as_map).expect("options");
        assert_eq!(map_bool(options, "rk"), Some(true));
        assert_eq!(map_bool(options, "up"), Some(true));
        assert_eq!(map_bool(options, "uv"), Some(true));
        assert_eq!(map_bool(options, "pinUvAuthToken"), Some(true));
        assert_eq!(map_bool(options, "credMgmt"), Some(true));

        let algorithms = map_value(&map, 10)
            .and_then(Value::as_array)
            .expect("algorithms");
        assert!(algorithms.iter().any(|algorithm| {
            algorithm.as_map().is_some_and(|algorithm| {
                map_integer(algorithm, "alg") == Some(COSE_ALG_ES256.into())
                    && map_text(algorithm, "type") == Some("public-key")
            })
        }));
    }

    #[test]
    fn empty_and_malformed_cbor_requests_return_ctap_errors() {
        let mut authenticator = Authenticator::default();
        assert_eq!(
            authenticator.handle_cbor(&[]),
            error_response(ErrorStatus::InvalidCommand)
        );
        assert_eq!(
            authenticator.handle_cbor(&[Ctap2Command::GetAssertion.into(), 0xff]),
            error_response(ErrorStatus::InvalidCbor)
        );
        assert_eq!(
            authenticator.handle_cbor(&[Ctap2Command::GetNextAssertion.into(), 0xa0]),
            error_response(ErrorStatus::InvalidCbor)
        );
    }

    #[test]
    fn make_auth_data_encodes_rp_hash_flags_and_counter() {
        let auth_data = make_auth_data("example.com", 0x05, 0x0102_0304, None, None);
        assert_eq!(&auth_data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth_data[32], 0x05);
        assert_eq!(&auth_data[33..37], &[1, 2, 3, 4]);
        assert_eq!(auth_data.len(), 37);
    }

    #[test]
    fn make_auth_data_sets_extension_flag_when_extensions_are_present() {
        let auth_data = make_auth_data(
            "example.com",
            0x41,
            0,
            Some((
                &[1, 2, 3, 4],
                &cose_public_key_coordinates(vec![5; 32], vec![6; 32]),
            )),
            Some(&cred_props_extension(true)),
        );

        assert_ne!(auth_data[32] & 0x80, 0);
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert_eq!(
            Authenticator::default().handle_cbor(&[0xff]),
            error_response(ErrorStatus::InvalidCommand)
        );
    }

    #[test]
    fn unsupported_commands_do_not_panic() {
        let mut authenticator = Authenticator::default();
        for command in [0x09, 0x0c, 0x0d, 0x40] {
            assert_eq!(
                authenticator.handle_cbor(&[command]),
                error_response(ErrorStatus::InvalidCommand)
            );
        }
    }

    #[test]
    fn protocol2_client_pin_round_trip_and_retry_state_persist() {
        let store_dir = test_store_dir("client-pin");
        let mut authenticator = Authenticator::new(store_dir.clone(), None);
        let client_secret = EphemeralSecret::generate();
        let server_key = client_pin_key_agreement(&mut authenticator);
        let server_public = parse_key_agreement(&server_key).expect("valid server public key");
        let (aes_key, hmac_key) = derive_protocol2_keys(
            client_secret
                .diffie_hellman(&server_public)
                .raw_secret_bytes()
                .as_slice(),
        )
        .expect("derive protocol 2 keys");
        let client_key = client_key_agreement(&client_secret);
        let mut padded_pin = vec![b'1', b'2', b'3', b'4'];
        padded_pin.resize(64, 0);
        let encrypted_pin = encrypt_aes(&aes_key, &padded_pin).expect("encrypt PIN");
        let set_params = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(encrypted_pin.clone()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
            ),
        ]);
        let set_response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(3.into())),
                (Value::Integer(3.into()), client_key.clone()),
                (Value::Integer(4.into()), set_params),
            ]),
        ));
        assert_eq!(set_response[0], 0x00);

        let retries = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(1.into())),
            ]),
        ));
        let Value::Map(retries_map) =
            ciborium::from_reader::<Value, _>(&retries[1..]).expect("CBOR")
        else {
            panic!("expected getRetries response");
        };
        assert_eq!(map_value(&retries_map, 3), Some(&Value::Integer(8.into())));

        let pin_hash = Sha256::digest(b"1234");
        let encrypted_pin_hash = encrypt_aes(&aes_key, &pin_hash[..16]).expect("encrypt PIN hash");
        let token_response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(6.into())),
                (Value::Integer(3.into()), client_key),
                (Value::Integer(6.into()), Value::Bytes(encrypted_pin_hash)),
                (Value::Integer(9.into()), Value::Integer(1.into())),
            ]),
        ));
        assert_eq!(token_response[0], 0x00);
        let Value::Map(token_map) =
            ciborium::from_reader::<Value, _>(&token_response[1..]).expect("CBOR")
        else {
            panic!("expected token response");
        };
        let encrypted_token = map_bytes(&token_map, 2).expect("encrypted token");
        assert_eq!(
            decrypt_aes(&aes_key, encrypted_token)
                .expect("decrypt token")
                .len(),
            32
        );

        let wrong_hash = Sha256::digest(b"9999");
        let wrong_encrypted_hash =
            encrypt_aes(&aes_key, &wrong_hash[..16]).expect("encrypt PIN hash");
        let wrong_response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(6.into())),
                (
                    Value::Integer(3.into()),
                    client_key_agreement(&client_secret),
                ),
                (Value::Integer(6.into()), Value::Bytes(wrong_encrypted_hash)),
                (Value::Integer(9.into()), Value::Integer(1.into())),
            ]),
        ));
        assert_eq!(wrong_response, vec![ErrorStatus::PinInvalid as u8]);

        let mut restored = Authenticator::new(store_dir.clone(), None);
        let restored_retries = restored.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(1.into())),
            ]),
        ));
        let Value::Map(restored_map) =
            ciborium::from_reader::<Value, _>(&restored_retries[1..]).expect("CBOR")
        else {
            panic!("expected restored getRetries response");
        };
        assert_eq!(map_value(&restored_map, 3), Some(&Value::Integer(7.into())));
        std::fs::remove_dir_all(store_dir).expect("remove test store");
    }

    #[test]
    fn protocol2_aes_and_hmac_use_separate_derived_keys() {
        let secret = [0x42; 32];
        let (aes_key, hmac_key) = derive_protocol2_keys(&secret).expect("derive keys");
        assert_ne!(aes_key, hmac_key);
        let plaintext = [0x11; 32];
        let encrypted = encrypt_aes(&aes_key, &plaintext).expect("encrypt");
        assert_eq!(
            decrypt_aes(&aes_key, &encrypted).expect("decrypt"),
            plaintext
        );
        assert!(verify_pin_uv_auth_param(&hmac_key, &[0u8; 16], &plaintext).is_err());
    }

    #[test]
    fn make_credential_with_pin_uv_auth_token_regression() {
        // Regression test for three related CTAP 2.1 PinUvAuthProtocol 2 bugs in the
        // pinUvAuthToken flow that broke browser (Chrome/Firefox) makeCredential and
        // getAssertion operations after a ClientPIN token exchange.
        //
        // Bug 1 — Missing key 3 in getPinUvAuthToken response (src/ctap2.rs ~1109):
        //   CTAP 2.1 Protocol 2 requires pinUvAuthParam (key 3) in the token response:
        //   HMAC-SHA256(hmac_key, encrypted_token)[0..16]. Before the fix, only key 2
        //   (encrypted token) was returned, which broke browser integrity verification.
        //
        // Bug 2 — Wrong HMAC message for makeCredential (src/ctap2.rs ~329):
        //   CTAP 2.1 §6.1.1 defines the pinUvAuthParam HMAC message for makeCredential as
        //   `clientDataHash || rpId`, not just `clientDataHash`. The old code only passed
        //   `client_data_hash`, so the HMAC never matched what the browser computed.
        //
        // Bug 3 — rp_id=None in makeCredential token check (src/ctap2.rs ~331):
        //   validate_pin_uv_auth compares the token's rp_id against the passed rp_id via
        //   `is_some_and(|token_rp_id| Some(token_rp_id) != rp_id)`. When rp_id=None,
        //   `Some(token_rp_id) != None` is always true, so every token with a scoped rp_id
        //   was rejected, even for the correct RP.
        let store_dir = test_store_dir("make-credential-token-regression");
        let mut authenticator = Authenticator::new(store_dir.clone(), None);

        // ── Setup: set PIN and get a token ──────────────────────────────────

        let client_secret = EphemeralSecret::generate();
        let server_key = client_pin_key_agreement(&mut authenticator);
        let server_public = parse_key_agreement(&server_key).expect("valid server public key");
        let (aes_key, hmac_key) = derive_protocol2_keys(
            client_secret
                .diffie_hellman(&server_public)
                .raw_secret_bytes()
                .as_slice(),
        )
        .expect("derive protocol 2 keys");
        let client_key = client_key_agreement(&client_secret);

        let mut padded_pin = vec![b'1', b'2', b'3', b'4'];
        padded_pin.resize(64, 0);
        let encrypted_pin = encrypt_aes(&aes_key, &padded_pin).expect("encrypt PIN");
        let set_params = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(encrypted_pin.clone()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
            ),
        ]);
        let set_response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(3.into())),
                (Value::Integer(3.into()), client_key),
                (Value::Integer(4.into()), set_params),
            ]),
        ));
        assert_eq!(set_response[0], 0x00, "setPin should succeed");

        // Get fresh key agreement for the token call
        let client_secret2 = EphemeralSecret::generate();
        let server_key2 = client_pin_key_agreement(&mut authenticator);
        let server_public2 = parse_key_agreement(&server_key2).expect("valid server public key");
        let (aes_key2, _) = derive_protocol2_keys(
            client_secret2
                .diffie_hellman(&server_public2)
                .raw_secret_bytes()
                .as_slice(),
        )
        .expect("derive protocol 2 keys");
        let pin_hash = Sha256::digest(b"1234");
        let encrypted_pin_hash = encrypt_aes(&aes_key2, &pin_hash[..16]).expect("encrypt PIN hash");
        let client_key2 = client_key_agreement(&client_secret2);
        let rp_id = "example.com";

        let token_response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(6.into())),
                (Value::Integer(3.into()), client_key2),
                (Value::Integer(6.into()), Value::Bytes(encrypted_pin_hash)),
                (Value::Integer(9.into()), Value::Integer(1.into())),
                (Value::Integer(10.into()), Value::Text(rp_id.to_owned())),
            ]),
        ));
        assert_eq!(token_response[0], 0x00, "getToken should succeed");
        let Value::Map(token_map) =
            ciborium::from_reader::<Value, _>(&token_response[1..]).expect("CBOR")
        else {
            panic!("expected token response map");
        };

        // Decrypt the token from key 2 for HMAC computations
        let encrypted_token = map_bytes(&token_map, 2).expect("encrypted token (key 2)");
        let token = decrypt_aes(&aes_key2, encrypted_token).expect("decrypt token");
        assert_eq!(token.len(), 32, "pinUvAuthToken must be 32 bytes");

        // key 3 (pinUvAuthParam) MUST equal HMAC-SHA256(token,
        // encryptedToken) over the full 32-byte digest (PIN/UV Auth
        // Protocol 2). This is exactly what libfido2 / browsers verify,
        // so a mismatch here is what makes a browser reject the token
        // and close the device.
        let expected_pin_uv_auth_param = {
            let mut mac = HmacSha256::new_from_slice(&token).expect("HMAC key");
            mac.update(encrypted_token);
            mac.finalize().into_bytes().to_vec()
        };
        let pin_uv_auth_param = map_bytes(&token_map, 3).expect("pinUvAuthParam (key 3)");
        assert_eq!(
            pin_uv_auth_param,
            expected_pin_uv_auth_param.as_slice(),
            "key 3 must be HMAC-SHA256(token, encryptedToken)"
        );

        // ── REGRESSION 2+3: validate_pin_uv_auth for makeCredential ─────────
        let client_data_hash = [0xcc; 32];

        // CTAP 2.1 §6.1.1: makeCredential message = clientDataHash || rpId
        let make_cred_message = [client_data_hash.as_slice(), rp_id.as_bytes()].concat();
        let mut mac = HmacSha256::new_from_slice(&token).expect("HMAC key");
        mac.update(&make_cred_message);
        // PIN/UV Auth Protocol 2 returns the full 32-byte HMAC (libfido2
        // cbor_encode_pin_auth: outlen = dgst_len for protocol 2).
        let correct_auth_param = mac.finalize().into_bytes().to_vec();

        // Should succeed: correct HMAC message + Some(rp_id)
        let result = authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&correct_auth_param),
            &make_cred_message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some(rp_id),
        );
        assert_eq!(
            result,
            Ok(true),
            "REGRESSION 2+3: clientDataHash||rpId + Some(rp_id) should pass"
        );

        // Simulate the old buggy server behavior: browser sends HMAC over
        // clientDataHash || rpId (CTAP 2.1 §6.1.1), but the server (before the
        // fix) only verified HMAC over clientDataHash. Since the HMAC messages
        // differ, the comparison should fail.
        let result = authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&correct_auth_param), // browser's HMAC = HMAC(token, clientDataHash || rpId)
            &client_data_hash,         // OLD server message = clientDataHash only (BUG)
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some(rp_id),
        );
        assert_eq!(
            result,
            Err(ErrorStatus::PinAuthInvalid),
            "REGRESSION 2: old server message (clientDataHash) vs browser's (clientDataHash||rpId)"
        );

        // Re-inject token (was cleared by the previous error return)
        authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
            rp_id: Some(rp_id.to_owned()),
            issued_at: Instant::now(),
        });

        // Should be rejected: Some(rp_id) token with None rp_id passed
        let result = authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&correct_auth_param),
            &make_cred_message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            None,
        );
        assert_eq!(
            result,
            Err(ErrorStatus::PinAuthInvalid),
            "REGRESSION 3: scoped token + None rp_id should be rejected"
        );

        // Token without rp_id should work for any rp_id
        authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
            rp_id: None,
            issued_at: Instant::now(),
        });
        let result = authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&correct_auth_param),
            &make_cred_message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some(rp_id),
        );
        assert_eq!(
            result,
            Ok(true),
            "token without rp_id should be valid for any rp_id"
        );

        // ── getAssertion HMAC: clientDataHash only (CTAP 2.1 §6.2.1) ───────
        authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token,
            permissions: Ctap2PermissionFlags::GET_ASSERTION,
            rp_id: Some(rp_id.to_owned()),
            issued_at: Instant::now(),
        });
        let mut mac =
            HmacSha256::new_from_slice(&authenticator.pin_uv_auth_token.as_ref().unwrap().value)
                .expect("HMAC key");
        mac.update(&client_data_hash);
        let assertion_auth_param = mac.finalize().into_bytes()[..16].to_vec();
        let result = authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&assertion_auth_param),
            &client_data_hash,
            Ctap2PermissionFlags::GET_ASSERTION,
            Some(rp_id),
        );
        assert_eq!(
            result,
            Ok(true),
            "getAssertion HMAC message is clientDataHash (§6.2.1)"
        );

        std::fs::remove_dir_all(store_dir).expect("remove test store");
    }

    #[test]
    fn credential_management_enumerates_discoverable_credentials_with_permission_token() {
        let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3]);
        let token = vec![0x33; 32];
        authenticator.client_pin = Some(ClientPinState {
            pin_salt: vec![0; 32],
            pin_verifier: vec![0; 32],
            retries: PIN_RETRIES,
        });
        authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
            rp_id: None,
            issued_at: Instant::now(),
        });

        let request = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Integer(2.into())),
            (
                Value::Integer(4.into()),
                Value::Bytes(management_pin_auth(&token, 1, None)),
            ),
        ]);
        let response =
            authenticator.handle_cbor(&ctap_request(Ctap2Command::CredentialManagement, request));
        assert_eq!(response[0], 0x00);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected credential-management response");
        };
        assert_eq!(map_value(&map, 1), Some(&Value::Integer(1.into())));
    }

    #[test]
    fn exclude_list_detects_existing_credential_for_same_rp() {
        let authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);
        let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

        assert!(excluded_credential_exists(
            &authenticator.credentials,
            "example.com",
            Some(&exclude_list)
        ));
    }

    #[test]
    fn exclude_list_ignores_matching_id_for_different_rp() {
        let authenticator = authenticator_with_credential("other.example", vec![1, 2, 3, 4]);
        let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

        assert!(!excluded_credential_exists(
            &authenticator.credentials,
            "example.com",
            Some(&exclude_list)
        ));
    }

    #[test]
    fn allow_list_absent_allows_any_credential() {
        assert!(allow_list_allows(None, &[1, 2, 3, 4]));
    }

    #[test]
    fn allow_list_absent_or_empty_allows_any_credential() {
        assert!(allow_list_allows(Some(&[]), &[1, 2, 3, 4]));
        assert!(allow_list_allows(None, &[1, 2, 3, 4]));
    }

    #[test]
    fn allow_list_non_matching_rejects_credential() {
        assert!(!allow_list_allows(
            Some(&[credential_descriptor(vec![9, 9, 9, 9])]),
            &[1, 2, 3, 4]
        ));
    }

    #[test]
    fn credential_descriptor_requires_public_key_type_and_matching_id() {
        let wrong_type = Value::Map(vec![
            (
                Value::Text("type".to_owned()),
                Value::Text("not-public-key".to_owned()),
            ),
            (Value::Text("id".to_owned()), Value::Bytes(vec![1, 2, 3, 4])),
        ]);
        let malformed = Value::Map(vec![(
            Value::Text("type".to_owned()),
            Value::Text("public-key".to_owned()),
        )]);

        assert!(!credential_descriptor_list_contains(
            &[wrong_type, malformed],
            &[1, 2, 3, 4]
        ));
        assert!(credential_descriptor_list_contains(
            &[credential_descriptor(vec![1, 2, 3, 4])],
            &[1, 2, 3, 4]
        ));
    }

    #[test]
    fn make_credential_options_accept_absent_up_true_and_rk() {
        assert_eq!(validate_make_credential_options(None), Ok(()));
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[
                ("up", true),
                ("rk", true),
                ("unknown", true),
            ]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("rk", false)]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("requireResidentKey", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "required"
            )]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "preferred"
            )]))),
            Ok(())
        );
        assert_eq!(
            validate_make_credential_options(Some(&options_text_map(&[(
                "residentKey",
                "surprise"
            )]))),
            Err(ErrorStatus::InvalidCbor)
        );
    }

    #[test]
    fn attestation_conveyance_accepts_common_browser_values() {
        assert_eq!(validate_attestation_conveyance(None), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("none")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("indirect")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("direct")), Ok(()));
        assert_eq!(validate_attestation_conveyance(Some("enterprise")), Ok(()));
        assert_eq!(
            validate_attestation_conveyance(Some("unexpected")),
            Err(ErrorStatus::InvalidCbor)
        );
    }

    #[test]
    fn get_assertion_options_accept_absent_and_up_true() {
        // Regression: webauthn.io sends authenticatorGetAssertion with up=false
        // (no uv=true), which was rejected as UnsupportedOption.
        assert_eq!(validate_get_assertion_options(None), Ok(()));
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", false)]))),
            Ok(())
        );
    }

    #[test]
    fn options_reject_required_user_verification() {
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("uv", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("uv", true)]))),
            Ok(())
        );
    }

    #[test]
    fn options_accept_disabled_user_presence_with_uv() {
        // Some sites (e.g. github.com) send up=false alongside uv=true on
        // makeCredential; this combination must also be accepted.
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("up", false), ("uv", true)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", false), ("uv", true)]))),
            Ok(())
        );
    }

    #[test]
    fn options_accept_disabled_user_presence_without_uv() {
        // Regression: webauthn.io sends authenticatorMakeCredential and
        // authenticatorGetAssertion with up=false but no uv=true.  Both
        // were rejected as UnsupportedOption.
        assert_eq!(
            validate_make_credential_options(Some(&options_map(&[("up", false)]))),
            Ok(())
        );
        assert_eq!(
            validate_get_assertion_options(Some(&options_map(&[("up", false)]))),
            Ok(())
        );
    }

    #[test]
    fn get_assertion_respects_the_requested_user_presence_flag() {
        for (requested, expected_flag) in [(true, 0x01), (false, 0x00)] {
            let mut authenticator =
                authenticator_with_credential("example.com", vec![u8::from(requested)]);
            let response = authenticator.handle_cbor(&ctap_request(
                Ctap2Command::GetAssertion,
                Value::Map(vec![
                    (
                        Value::Integer(1.into()),
                        Value::Text("example.com".to_owned()),
                    ),
                    (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                    (
                        Value::Integer(5.into()),
                        Value::Map(options_map(&[("up", requested)])),
                    ),
                ]),
            ));
            assert_eq!(response[0], 0x00);
            let Value::Map(response) =
                ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
            else {
                panic!("expected assertion map");
            };
            let auth_data = map_bytes(&response, 2).expect("authenticator data");
            assert_eq!(auth_data[32] & 0x01, expected_flag);
            std::fs::remove_dir_all(&authenticator.store_dir).expect("remove test store");
        }
    }

    #[test]
    fn multiple_matching_credentials_include_number_of_credentials_and_support_next_assertion() {
        let mut authenticator = authenticator_with_credentials(
            "example.com",
            vec![
                test_credential(vec![1], "example.com", 1),
                test_credential(vec![2], "example.com", 2),
            ],
        );

        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            ]),
        ));

        assert_eq!(response[0], 0x00);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected assertion map");
        };
        assert_eq!(map_value(&map, 5), Some(&Value::Integer(2.into())));

        let next = authenticator.handle_cbor(&[Ctap2Command::GetNextAssertion.into()]);
        assert_eq!(next[0], 0x00);
        let Value::Map(next_map) = ciborium::from_reader::<Value, _>(&next[1..]).expect("CBOR")
        else {
            panic!("expected next assertion map");
        };
        assert_eq!(map_value(&next_map, 5), None);

        let first_id = map_value(&map, 1)
            .and_then(Value::as_map)
            .and_then(|map| map_bytes(map, "id"))
            .expect("first credential id");
        let next_id = map_value(&next_map, 1)
            .and_then(Value::as_map)
            .and_then(|map| map_bytes(map, "id"))
            .expect("next credential id");
        assert_ne!(first_id, next_id);
    }

    #[test]
    fn absent_allow_list_excludes_non_discoverable_credentials() {
        let mut authenticator = authenticator_with_credentials(
            "example.com",
            vec![
                test_credential(vec![1], "example.com", 1),
                test_credential(vec![2], "example.com", 2),
            ],
        );
        authenticator.credentials[1].discoverable = false;

        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            ]),
        ));
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected assertion map");
        };
        assert_eq!(map_value(&map, 5), None);
        assert_eq!(
            map_value(&map, 1)
                .and_then(Value::as_map)
                .and_then(|map| map_bytes(map, "id")),
            Some(&[1][..])
        );
    }

    #[test]
    fn malformed_allow_list_and_exclude_list_are_rejected() {
        let mut authenticator = Authenticator::default();

        let make_credential = ctap_request(
            Ctap2Command::MakeCredential,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 32])),
                (
                    Value::Integer(2.into()),
                    Value::Map(vec![(
                        Value::Text("id".to_owned()),
                        Value::Text("example.com".to_owned()),
                    )]),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::Text("type".to_owned()),
                            Value::Text("public-key".to_owned()),
                        ),
                        (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                    ])]),
                ),
                (
                    Value::Integer(5.into()),
                    Value::Array(vec![Value::Text("not-a-descriptor".to_owned())]),
                ),
                (
                    Value::Integer(7.into()),
                    Value::Map(vec![(Value::Text("up".to_owned()), Value::Bool(true))]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

        let get_assertion = ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                (
                    Value::Integer(3.into()),
                    Value::Array(vec![Value::Text("bad-entry".to_owned())]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
    }

    #[test]
    fn empty_allow_list_matches_discoverable_credentials() {
        let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);

        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                (Value::Integer(3.into()), Value::Array(Vec::new())),
            ]),
        ));

        assert_eq!(response[0], 0x00);
    }

    #[test]
    fn client_data_hash_must_be_32_bytes() {
        let mut authenticator = Authenticator::default();

        let make_credential = ctap_request(
            Ctap2Command::MakeCredential,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 31])),
                (
                    Value::Integer(2.into()),
                    Value::Map(vec![(
                        Value::Text("id".to_owned()),
                        Value::Text("example.com".to_owned()),
                    )]),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::Text("type".to_owned()),
                            Value::Text("public-key".to_owned()),
                        ),
                        (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                    ])]),
                ),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

        let get_assertion = ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 33])),
            ]),
        );
        assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
    }

    #[test]
    fn display_rp_label_prefers_human_readable_name() {
        assert_eq!(
            display_rp_label(Some("Weird Site"), "example.com"),
            "Weird Site (example.com)"
        );
        assert_eq!(
            display_rp_label(Some("example.com"), "example.com"),
            "example.com"
        );
        assert_eq!(display_rp_label(None, "example.com"), "example.com");
    }

    #[test]
    fn unsupported_policy_version_rejects_assertion() {
        let mut authenticator = authenticator_with_credentials(
            "example.com",
            vec![test_credential(vec![1], "example.com", 1)],
        );
        authenticator.credentials[0].policy = Some(store::StoredPcrPolicy {
            selection: "sha256:7".to_owned(),
            digest: vec![15; 32],
            policy_ref: None,
            authority_name: None,
            authority_signature: None,
            policy_version: 99,
        });

        let get_assertion = ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            ]),
        );
        let response = authenticator.handle_cbor(&get_assertion);
        assert_eq!(response[0], 0x27);
    }

    fn authenticator_with_credential(rp_id: &str, credential_id: Vec<u8>) -> Authenticator {
        authenticator_with_credentials(rp_id, vec![test_credential(credential_id, rp_id, 0)])
    }

    fn authenticator_with_credentials(
        rp_id: &str,
        credentials: Vec<StoredCredentialTest>,
    ) -> Authenticator {
        let store_dir = test_store_dir("authenticator");
        let stored_credentials: Vec<_> = credentials
            .iter()
            .map(|credential| store::StoredCtap2Credential {
                id: credential.id.clone(),
                rp_id: rp_id.to_owned(),
                discoverable: true,
                user_id: Some(1000),
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
                policy: None,
                recovery: None,
                sign_count: credential.sign_count,
                integrity_mac: None,
            })
            .collect();
        store::save_ctap2_credentials_to_dir(&store_dir, &stored_credentials)
            .expect("save test credentials");
        Authenticator {
            store_dir,
            tpm_path: None,
            tpm: None,
            session: session::SessionContext::detect(),
            credentials: credentials
                .into_iter()
                .map(|credential| Credential {
                    id: credential.id,
                    rp_id: rp_id.to_owned(),
                    discoverable: true,
                    user_id: Some(1000),
                    user_handle: credential.user_handle,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key: credential.key,
                    policy: None,
                    recovery: None,
                    sign_count: credential.sign_count,
                })
                .collect(),
            pending_assertion: None,
            client_pin: None,
            key_agreement: None,
            pin_uv_auth_token: None,
            uv_satisfied: false,
            management: None,
        }
    }

    struct StoredCredentialTest {
        id: Vec<u8>,
        user_handle: Vec<u8>,
        user_name: Option<String>,
        user_display_name: Option<String>,
        key: tpm::TpmCredential,
        sign_count: u32,
    }

    fn test_point() -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(&[0xabu8; 32]).expect("valid secret key");
        let pk = sk.public_key();
        let point = pk.to_sec1_point(false);
        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
    }

    fn test_credential(id: Vec<u8>, rp_id: &str, sign_count: u32) -> StoredCredentialTest {
        let user_suffix = id.first().copied().unwrap_or_default();
        let (x, y) = test_point();
        StoredCredentialTest {
            id,
            user_handle: vec![5, 6, 7, 8],
            user_name: Some(format!("user-{user_suffix}")),
            user_display_name: Some(format!("Test User {rp_id}")),
            key: tpm::TpmCredential {
                private: vec![9],
                public: vec![10],
                public_key_x: x,
                public_key_y: y,
                auth_value: None,
            },
            sign_count,
        }
    }

    fn ctap_request(command: Ctap2Command, body: Value) -> Vec<u8> {
        let mut payload = vec![command.into()];
        ciborium::into_writer(&body, &mut payload).expect("serialize CTAP request");
        payload
    }

    fn test_store_dir(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "linux-tpm-fido2-ctap2-test-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn credential_descriptor(id: Vec<u8>) -> Value {
        Value::Map(vec![
            (
                Value::Text("type".to_owned()),
                Value::Text("public-key".to_owned()),
            ),
            (Value::Text("id".to_owned()), Value::Bytes(id)),
        ])
    }

    fn client_pin_key_agreement(authenticator: &mut Authenticator) -> Vec<(Value, Value)> {
        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(2.into()), Value::Integer(2.into())),
            ]),
        ));
        let Value::Map(response) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
        else {
            panic!("expected key agreement response");
        };
        map_value(&response, 1)
            .and_then(Value::as_map)
            .expect("server key agreement")
            .to_vec()
    }

    fn client_key_agreement(secret: &EphemeralSecret) -> Value {
        let public_key = secret.public_key().to_sec1_bytes();
        cose_key_agreement_coordinates(public_key[1..33].to_vec(), public_key[33..65].to_vec())
    }

    fn pin_auth_param(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(message);
        mac.finalize().into_bytes()[..16].to_vec()
    }

    fn management_pin_auth(
        key: &[u8],
        sub_command: i128,
        params: Option<&[(Value, Value)]>,
    ) -> Vec<u8> {
        let message = management_auth_message(sub_command, params);
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(&message);
        mac.finalize().into_bytes()[..16].to_vec()
    }

    fn options_map(options: &[(&str, bool)]) -> Vec<(Value, Value)> {
        options
            .iter()
            .map(|(key, value)| (Value::Text((*key).to_owned()), Value::Bool(*value)))
            .collect()
    }

    fn options_text_map(options: &[(&str, &str)]) -> Vec<(Value, Value)> {
        options
            .iter()
            .map(|(key, value)| {
                (
                    Value::Text((*key).to_owned()),
                    Value::Text((*value).to_owned()),
                )
            })
            .collect()
    }
}
