use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use bitflags::bitflags;
use color_eyre::eyre::WrapErr;
use zeroize::Zeroizing;

use crate::{
    approval,
    credential::Credential,
    recovery::{self, UnlockedRecovery},
    store, tpm,
};
use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt};
use cbc::cipher::{KeyIvInit, block_padding::NoPadding};
use ciborium::{cbor, value::Value};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::Generate};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

mod authenticator_data;
mod cbor_codec;
mod protocol;

use authenticator_data::*;
use cbor_codec::*;
pub use protocol::{Ctap2Command, UnknownCtapCommandError, command_name};
use protocol::{ErrorStatus, MAX_MSG_SIZE};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

const PIN_UV_AUTH_PROTOCOL: u64 = 2;
const PIN_RETRIES: u32 = 8;
const UV_RETRIES: u32 = 8;
const PIN_KDF_ROUNDS: u32 = 100_000;
const MAX_RESIDENT_CREDENTIALS: usize = 128;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Ctap2PermissionFlags: u8 {
        const MAKE_CREDENTIAL = 1 << 0;
        const GET_ASSERTION = 1 << 1;
        const CREDENTIAL_MANAGEMENT = 1 << 2;
        const BIO_ENROLLMENT = 1 << 3;
        const LARGE_BLOB_WRITE = 1 << 4;
        const AUTHENTICATOR_CONFIGURATION = 1 << 5;
        const PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY = 1 << 6;
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
    approval: Box<dyn approval::UserApproval>,
    recovery_unlock: Option<UnlockedRecovery>,
    credentials: Vec<Credential>,
    pending_assertion: Option<PendingAssertion>,
    client_pin: Option<ClientPinState>,
    key_agreement: Option<EphemeralSecret>,
    pin_uv_auth_token: Option<PinUvAuthToken>,
    consecutive_pin_mismatches: u8,
    management: Option<ManagementState>,
    powered_up_at: Instant,
    operation_cancelled: Option<Arc<AtomicBool>>,
    operation_status: Option<Arc<AtomicU8>>,
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
    first_used_at: Option<Instant>,
    user_present_until: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagementContinuation {
    RelyingParties,
    Credentials,
}

struct ManagementState {
    continuation: ManagementContinuation,
    rp_indexes: Vec<usize>,
    rp_position: usize,
    credential_indexes: Vec<usize>,
    credential_position: usize,
    token: Vec<u8>,
    last_used_at: Instant,
}

struct PendingAssertion {
    rp_id: String,
    client_data_hash: Vec<u8>,
    credential_indexes: Vec<usize>,
    total_credentials: usize,
    created_at: Instant,
    user_presence: bool,
    user_verified: bool,
}

impl Authenticator {
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        Self::new_with_approval(store_dir, tpm_path, Box::new(approval::SystemApproval))
    }

    pub fn new_with_approval(
        store_dir: PathBuf,
        tpm_path: Option<PathBuf>,
        approval: Box<dyn approval::UserApproval>,
    ) -> Self {
        let tpm = None;
        let credentials = Self::load_credentials_from_disk(&store_dir);
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
            approval,
            recovery_unlock: None,
            credentials,
            pending_assertion: None,
            client_pin,
            key_agreement: None,
            pin_uv_auth_token: None,
            consecutive_pin_mismatches: 0,
            management: None,
            powered_up_at: Instant::now(),
            operation_cancelled: None,
            operation_status: None,
        }
    }

    fn load_credentials_from_disk(store_dir: &PathBuf) -> Vec<Credential> {
        match store::load_ctap2_credentials_from_dir(store_dir) {
            Ok(credentials) => credentials.into_iter().map(Credential::from).collect(),
            Err(error) => {
                log::warn!("failed to reload CTAP2 credential store: {error:?}");
                Vec::new()
            }
        }
    }

    pub fn handle_cbor_controlled(
        &mut self,
        payload: &[u8],
        cancelled: Arc<AtomicBool>,
        status: Arc<AtomicU8>,
    ) -> Vec<u8> {
        self.operation_cancelled = Some(cancelled.clone());
        self.operation_status = Some(status);
        let response = self.handle_cbor(payload);
        self.operation_cancelled = None;
        self.operation_status = None;
        if cancelled.load(Ordering::SeqCst) {
            self.cancel_pending();
            return error_response(ErrorStatus::KeepaliveCancel);
        }
        response
    }

    pub fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        if payload.len() > MAX_MSG_SIZE {
            return error_response(ErrorStatus::RequestTooLarge);
        }
        let Some((&command, body)) = payload.split_first() else {
            return error_response(ErrorStatus::InvalidCommand);
        };

        let command_byte = command;
        let Ok(command) = Ctap2Command::try_from(command_byte) else {
            log::info!("ctap2 request command=unknown code={command_byte:#04x}");
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

        log::info!(
            "ctap2 request command={} code={command_byte:#04x} body_len={}",
            command_name(command),
            body.len()
        );

        let result = match command {
            Ctap2Command::GetInfo => body
                .is_empty()
                .then(|| get_info_response(self.client_pin.is_some()))
                .ok_or(ErrorStatus::InvalidCbor),
            Ctap2Command::ClientPin => self.client_pin(body),
            Ctap2Command::MakeCredential => self.make_credential(body),
            Ctap2Command::GetAssertion => self.get_assertion(body),
            Ctap2Command::GetNextAssertion => self.get_next_assertion(body),
            Ctap2Command::CredentialManagement => self.credential_management(body),
            Ctap2Command::CredentialManagementPreview => Err(ErrorStatus::InvalidCommand),
            Ctap2Command::Reset => {
                if body.is_empty() {
                    self.reset()
                } else {
                    Err(ErrorStatus::InvalidCbor)
                }
            }
            Ctap2Command::Selection => {
                if body.is_empty() {
                    self.selection()
                } else {
                    Err(ErrorStatus::InvalidCbor)
                }
            }
            Ctap2Command::BioEnrollment | Ctap2Command::BioEnrollmentPreview => {
                self.bio_enrollment(body)
            }
            Ctap2Command::LargeBlobs => self.large_blobs(body),
            Ctap2Command::Config => self.config(body),
        };
        match result {
            Ok(response) => {
                log::debug!(
                    "ctap2 response command={} status=success response_len={}",
                    command_name(command),
                    response.len()
                );
                response
            }
            Err(status) => {
                log::info!(
                    "ctap2 response command={} status={status:?} code={:#04x}",
                    command_name(command),
                    u8::from(status)
                );
                error_response(status)
            }
        }
    }

    pub fn cancel_pending(&mut self) {
        self.pending_assertion = None;
        self.management = None;
        self.pin_uv_auth_token = None;
        self.key_agreement = None;
    }

    /// authenticatorReset (0x07): factory-resets the authenticator, deleting all
    /// credentials and clearing the configured PIN. CTAP2.2 §6.6 requires user
    /// presence (and, when set, alwaysUv) before performing the reset.
    fn reset(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        if self.powered_up_at.elapsed() > Duration::from_secs(10) {
            return Err(ErrorStatus::NotAllowed);
        }
        if !self.user_presence_approved("Reset FIDO authenticator and delete all passkeys", "reset")
        {
            return Err(ErrorStatus::OperationDenied);
        }
        store::delete_client_pin_state_from_dir(&self.store_dir).map_err(|error| {
            log::warn!("failed to delete client PIN state during reset: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        for credential in &self.credentials {
            store::delete_ctap2_credential_from_dir(&self.store_dir, &credential.id).map_err(
                |error| {
                    log::warn!("failed to delete credential during reset: {error:?}");
                    ErrorStatus::OperationDenied
                },
            )?;
        }
        self.credentials.clear();
        self.recovery_unlock = None;
        self.client_pin = None;
        self.key_agreement = None;
        self.pin_uv_auth_token = None;
        self.pending_assertion = None;
        self.management = None;
        Ok(vec![0x00])
    }

    /// authenticatorSelection (0x0B): returns success once
    /// the user has given consent. CTAP2.2 §6.9. The actual user gesture is
    /// collected by the transport/UI; here we just confirm approval.
    fn selection(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        if !self.user_presence_approved("Select this FIDO authenticator", "selection") {
            return Err(ErrorStatus::OperationDenied);
        }
        Ok(vec![0x00])
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
        validate_make_credential_entities(rp, user)?;
        let params = map_array(&request, 4).ok_or(ErrorStatus::MissingParameter)?;
        validate_pub_key_cred_params(params)?;
        let exclude_list = optional_array(&request, 5)?;
        let extensions = optional_map(&request, 6)?;
        validate_cred_props_extension(extensions)?;
        let cred_props_requested =
            extensions.is_some_and(|extensions| map_bool(extensions, "credProps") == Some(true));
        validate_attestation_formats(optional_array(&request, 11)?)?;
        if map_value(&request, 10).is_some() {
            return Err(ErrorStatus::InvalidParameter);
        }

        let rp_id = map_text(rp, "id").ok_or(ErrorStatus::MissingParameter)?;
        let rp_name = map_text(rp, "name");
        let user_handle = map_bytes(user, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");
        let pin_uv_auth_param = optional_bytes(&request, 8)?;
        let pin_uv_auth_protocol = optional_integer(&request, 9)?;
        if pin_uv_auth_param == Some(&[]) {
            return self.zero_length_pin_uv_auth("Select authenticator for registration");
        }
        let pin_uv_auth_present = pin_uv_auth_param.is_some();
        let user_verified = self.validate_pin_uv_auth(
            pin_uv_auth_protocol,
            pin_uv_auth_param,
            client_data_hash,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some(rp_id),
        )?;
        let options = optional_map(&request, 7)?;
        if let Some(options) = options {
            log::debug!("makeCredential options: {options:?}");
        }
        validate_make_credential_options(options)?;
        let uv_requested = !pin_uv_auth_present
            && options.is_some_and(|options| map_bool(options, "uv") == Some(true));
        let discoverable = options.and_then(|options| map_bool(options, "rk")) == Some(true);
        validate_credential_descriptor_list(exclude_list, true)?;
        let replacement_index = discoverable
            .then(|| {
                self.credentials.iter().position(|credential| {
                    credential.discoverable
                        && credential.rp_id == rp_id
                        && credential.user_handle == user_handle
                })
            })
            .flatten();
        if discoverable
            && replacement_index.is_none()
            && self
                .credentials
                .iter()
                .filter(|credential| credential.discoverable)
                .count()
                >= MAX_RESIDENT_CREDENTIALS
        {
            return Err(ErrorStatus::KeyStoreFull);
        }
        if discoverable && !user_verified && !uv_requested {
            return Err(if self.client_pin.is_some() {
                ErrorStatus::PuatRequired
            } else {
                ErrorStatus::OperationDenied
            });
        }

        if self.operation_is_cancelled() {
            log::error!("operation cancelled before registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        let cached_user_presence =
            user_verified && self.pin_uv_auth_token_has_cached_user_presence();
        let prompt = format!(
            "Register a new passkey for {} as {}",
            display_rp_label(rp_name, rp_id),
            user_display_name.or(user_name).unwrap_or("unknown user")
        );
        if !cached_user_presence
            && !self.user_presence_approved(&prompt, &format!("registration for {rp_id}"))
        {
            return Err(ErrorStatus::OperationDenied);
        }
        let user_verified = user_verified || uv_requested;
        self.consume_pin_uv_auth_token_after_user_presence();

        if excluded_credential_exists(&self.credentials, rp_id, exclude_list) {
            log::info!("makeCredential excluded existing credential for rp_id={rp_id}");
            return Err(ErrorStatus::CredentialExcluded);
        }

        if self.operation_is_cancelled() {
            log::error!("operation cancelled during registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        let recovery_config = store::load_recovery_config(&self.store_dir).map_err(|error| {
            log::warn!("failed to load recovery configuration: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        let recovery_unlock = if recovery_config.is_some() {
            Some(
                self.recovery_unlock
                    .clone()
                    .filter(|unlocked| {
                        unlocked.matches_configuration(recovery_config.as_ref().unwrap())
                    })
                    .ok_or_else(|| {
                        log::warn!("recovery enrollment is locked; run config unlock-recovery");
                        ErrorStatus::OperationDenied
                    })?,
            )
        } else {
            None
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
        let recovery_key = if recovery_unlock.is_some() {
            Some(tpm.create_recovery_key().map_err(|error| {
                log::warn!("failed to create TPM recovery key: {error:?}");
                ErrorStatus::OperationDenied
            })?)
        } else {
            None
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
        if let Some(authority) = &recovery_key {
            let policy_ref = tpm::credential_policy_ref(&credential_id);
            policy = match tpm.create_authorized_policy(&policy, authority, &policy_ref) {
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
        let recovery = match (recovery_key, recovery_unlock) {
            (Some(authority), Some(unlocked)) => {
                let aad = recovery::credential_aad(
                    &credential_id,
                    &authority.public,
                    policy.policy_ref.as_deref().expect("authorized policyRef"),
                );
                let encrypted_auth = unlocked
                    .encrypt(
                        authority.auth_value.as_ref().expect("random recovery auth"),
                        &aad,
                    )
                    .map_err(|error| {
                        log::warn!("failed to encrypt recovery authorization: {error:?}");
                        ErrorStatus::OperationDenied
                    })?;
                Some(store::StoredRecoverySlot {
                    label: None,
                    encrypted_auth,
                    last_used: None,
                    used_count: 0,
                    key: store::StoredTpmKey {
                        private: authority.private,
                        public: authority.public,
                        public_key_x: authority.public_key_x,
                        public_key_y: authority.public_key_y,
                    },
                })
            }
            _ => None,
        };
        let public_key = cose_credential_public_key(&key);

        let extensions = cred_props_requested.then(|| cred_props_extension(discoverable));
        let auth_data = make_auth_data(
            rp_id,
            0x41 | if user_verified { 0x04 } else { 0 },
            0,
            Some((&credential_id, &public_key)),
            extensions.as_ref(),
        );
        let previous_credentials = self.credentials.clone();
        if let Some(index) = replacement_index {
            self.credentials.remove(index);
        }
        self.credentials.push(Credential {
            id: credential_id,
            rp_id: rp_id.to_owned(),
            discoverable,
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
        if let Err(error) = self.save_credentials() {
            self.credentials = previous_credentials;
            return Err(error);
        }

        log::info!(
            "created TPM-backed credential rp_id={} total_credentials={}",
            rp_id,
            self.credentials.len()
        );

        let response = encode_response(
            cbor!({
                1 => "none",
                2 => byte_string(auth_data),
                3 => {},
            })
            .unwrap(),
        );
        log::debug!("makeCredential response response_len={}", response.len());
        Ok(response)
    }

    fn get_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;

        let rp_id = map_text(&request, 1).ok_or(ErrorStatus::MissingParameter)?;
        let client_data_hash = map_bytes(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let pin_uv_auth_param = optional_bytes(&request, 6)?;
        let pin_uv_auth_protocol = optional_integer(&request, 7)?;
        if pin_uv_auth_param == Some(&[]) {
            return self.zero_length_pin_uv_auth("Select authenticator for assertion");
        }
        let pin_uv_auth_present = pin_uv_auth_param.is_some();
        let user_verified = self.validate_pin_uv_auth(
            pin_uv_auth_protocol,
            pin_uv_auth_param,
            client_data_hash,
            Ctap2PermissionFlags::GET_ASSERTION,
            Some(rp_id),
        )?;
        let allow_list = optional_array(&request, 3)?;
        let _extensions = optional_map(&request, 4)?;
        let options = optional_map(&request, 5)?;
        validate_get_assertion_options(options)?;
        let uv_requested = !pin_uv_auth_present
            && options.is_some_and(|options| map_bool(options, "uv") == Some(true));
        let user_presence = options.and_then(|options| map_bool(options, "up")) != Some(false);
        validate_credential_descriptor_list(allow_list, true)?;

        // Reload credentials from disk when running as daemon (tpm_path is set)
        // to pick up management-side modifications (e.g., update-pcr-reference).
        if self.tpm_path.is_some() {
            self.credentials = Self::load_credentials_from_disk(&self.store_dir);
        }
        let credential_indexes = matching_credential_indexes(&self.credentials, rp_id, allow_list);
        let Some((&credential_index, remaining_indexes)) = credential_indexes.split_first() else {
            return Err(ErrorStatus::NoCredentials);
        };

        let cached_user_presence =
            user_verified && self.pin_uv_auth_token_has_cached_user_presence();
        if (user_presence || uv_requested)
            && !(user_presence && cached_user_presence)
            && !self.assertion_approved(rp_id)
        {
            return Err(ErrorStatus::OperationDenied);
        }
        let user_verified = user_verified || uv_requested;
        let user_presence = user_presence || uv_requested;
        if user_presence {
            self.consume_pin_uv_auth_token_after_user_presence();
        }

        self.pending_assertion = if remaining_indexes.is_empty() || allow_list.is_some() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: rp_id.to_owned(),
                client_data_hash: client_data_hash.to_vec(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: credential_indexes.len(),
                created_at: Instant::now(),
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

            let user = credential_user_entity(credential, user_verified);

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
            allow_list.is_none().then_some(user),
            if allow_list.is_none() {
                credential_indexes.len()
            } else {
                0
            },
        ))
    }

    fn get_next_assertion(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        if !body.is_empty() {
            return Err(ErrorStatus::InvalidCbor);
        }

        let Some(pending) = self.pending_assertion.take() else {
            return Err(ErrorStatus::NotAllowed);
        };

        if pending.created_at.elapsed() > Duration::from_secs(30) {
            return Err(ErrorStatus::NotAllowed);
        }

        let Some((&credential_index, remaining_indexes)) = pending.credential_indexes.split_first()
        else {
            return Err(ErrorStatus::NotAllowed);
        };

        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: pending.rp_id.clone(),
                client_data_hash: pending.client_data_hash.clone(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: pending.total_credentials,
                created_at: Instant::now(),
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
        let user = credential_user_entity(credential, pending.user_verified);

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
            Some(user),
            0,
        ))
    }

    fn client_pin(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;
        let protocol = map_integer(&request, 1);
        let sub_command = map_integer(&request, 2).ok_or(ErrorStatus::MissingParameter)?;
        if !matches!(sub_command, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 9) {
            return Err(ErrorStatus::InvalidSubcommand);
        }
        if matches!(sub_command, 1 | 7) {
            if protocol.is_some() {
                validate_pin_uv_protocol(protocol)?;
            }
        } else {
            validate_pin_uv_protocol(protocol)?;
        }
        log::debug!(
            "clientPIN request subcommand={} code={sub_command:#04x}",
            client_pin_subcommand_name(sub_command)
        );
        let key_agreement = map_map(&request, 3);

        match sub_command {
            1 => {
                let retries = i64::from(
                    self.client_pin
                        .as_ref()
                        .map_or(PIN_RETRIES, |pin| pin.retries),
                );
                let response = if self.consecutive_pin_mismatches >= 3 {
                    cbor!({ 3 => retries, 4 => true })
                } else {
                    cbor!({ 3 => retries })
                }
                .expect("PIN retries response");
                Ok(encode_response(response))
            }
            2 => {
                self.key_agreement = Some(EphemeralSecret::generate());
                Ok(key_agreement_response(
                    self.key_agreement.as_ref().expect("just generated"),
                ))
            }
            3 => self.set_pin(
                key_agreement,
                map_bytes(&request, 5).ok_or(ErrorStatus::MissingParameter)?,
                map_bytes(&request, 4).ok_or(ErrorStatus::MissingParameter)?,
            ),
            4 => self.change_pin(
                key_agreement,
                map_bytes(&request, 5).ok_or(ErrorStatus::MissingParameter)?,
                map_bytes(&request, 6).ok_or(ErrorStatus::MissingParameter)?,
                map_bytes(&request, 4).ok_or(ErrorStatus::MissingParameter)?,
            ),
            5 => {
                if map_value(&request, 9).is_some() || map_value(&request, 10).is_some() {
                    return Err(ErrorStatus::InvalidParameter);
                }
                self.get_pin_uv_auth_token(
                    key_agreement,
                    map_bytes(&request, 6).ok_or(ErrorStatus::MissingParameter)?,
                    0x03,
                    None,
                    true,
                )
            }
            6 => self.get_pin_uv_auth_token_using_uv(
                key_agreement,
                pin_uv_permissions(&request).ok_or(ErrorStatus::MissingParameter)?,
                map_text(&request, 10).map(str::to_owned),
            ),
            7 => Ok(encode_response(
                cbor!({
                    5 => UV_RETRIES,
                })
                .unwrap(),
            )),
            9 => self.get_pin_uv_auth_token(
                key_agreement,
                map_bytes(&request, 6).ok_or(ErrorStatus::MissingParameter)?,
                pin_uv_permissions(&request).ok_or(ErrorStatus::MissingParameter)?,
                map_text(&request, 10).map(str::to_owned),
                false,
            ),
            _ => unreachable!("validated ClientPIN subcommand"),
        }
    }

    fn credential_management(&mut self, body: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
        let request = decode_map(body)?;
        let sub_command = optional_integer(&request, 1)?.ok_or(ErrorStatus::MissingParameter)?;
        if !(1..=7).contains(&sub_command) {
            return Err(ErrorStatus::InvalidSubcommand);
        }
        let params = optional_map(&request, 2)?;
        let protocol = optional_integer(&request, 3)?;
        let auth_param = optional_bytes(&request, 4)?;

        if sub_command == 3 {
            return self.enumerate_rps_next();
        }
        if sub_command == 5 {
            return self.enumerate_credentials_next();
        }

        // Any operation other than the matching continuation interrupts prior
        // enumeration state.
        self.management = None;
        let auth_param = auth_param.ok_or(ErrorStatus::PuatRequired)?;
        let protocol = protocol.ok_or(ErrorStatus::MissingParameter)?;
        let permission_rp_id = match sub_command {
            1 | 2 => None,
            4 => {
                validate_enumerate_credentials_params(params)?;
                None
            }
            6 => self.credential_rp_id_for_params(params, false)?,
            7 => self.credential_rp_id_for_params(params, true)?,
            _ => unreachable!("continuation commands returned above"),
        };
        let mut message = vec![sub_command as u8];
        if let Some(params) = encoded_map_value(body, 2)? {
            message.extend_from_slice(params);
        }
        self.validate_pin_uv_auth(
            Some(protocol),
            Some(auth_param),
            &message,
            Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
            permission_rp_id.as_deref(),
        )?;

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
            4 => self.enumerate_credentials_begin(params),
            6 => self.delete_credential(params),
            7 => self.update_user_information(params),
            _ => unreachable!("validated credential-management subcommand"),
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
            continuation: ManagementContinuation::RelyingParties,
            rp_indexes,
            rp_position: 1,
            credential_indexes: Vec::new(),
            credential_position: 0,
            token: self
                .pin_uv_auth_token
                .as_ref()
                .expect("credential management token was validated")
                .value
                .clone(),
            last_used_at: Instant::now(),
        });
        Ok(encode_rp_response(&self.credentials[first], Some(total)))
    }

    fn enumerate_rps_next(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        self.validate_management_continuation(ManagementContinuation::RelyingParties)?;
        let state = self.management.as_mut().ok_or(ErrorStatus::NotAllowed)?;
        let index = *state
            .rp_indexes
            .get(state.rp_position)
            .ok_or(ErrorStatus::NotAllowed)?;
        state.rp_position += 1;
        state.last_used_at = Instant::now();
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
            continuation: ManagementContinuation::Credentials,
            rp_indexes: Vec::new(),
            rp_position: 0,
            credential_indexes: indexes,
            credential_position: 1,
            token: self
                .pin_uv_auth_token
                .as_ref()
                .expect("credential management token was validated")
                .value
                .clone(),
            last_used_at: Instant::now(),
        });
        Ok(encode_credential_management_response(
            &self.credentials[first],
            Some(total),
        ))
    }

    fn enumerate_credentials_next(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        self.validate_management_continuation(ManagementContinuation::Credentials)?;
        let state = self.management.as_mut().ok_or(ErrorStatus::NotAllowed)?;
        let index = *state
            .credential_indexes
            .get(state.credential_position)
            .ok_or(ErrorStatus::NotAllowed)?;
        state.credential_position += 1;
        state.last_used_at = Instant::now();
        Ok(encode_credential_management_response(
            &self.credentials[index],
            None,
        ))
    }

    fn credential_rp_id_for_params(
        &self,
        params: Option<&[(Value, Value)]>,
        require_user: bool,
    ) -> Result<Option<String>, ErrorStatus> {
        let id = management_credential_id(params)?;
        if require_user {
            validate_management_user(params)?;
        }
        Ok(self
            .credentials
            .iter()
            .find(|credential| credential.discoverable && credential.id == id)
            .map(|credential| credential.rp_id.clone()))
    }

    fn validate_management_continuation(
        &mut self,
        expected: ManagementContinuation,
    ) -> Result<(), ErrorStatus> {
        let valid = self.management.as_ref().is_some_and(|state| {
            state.continuation == expected
                && state.last_used_at.elapsed() <= Duration::from_secs(30)
                && self.pin_uv_auth_token.as_ref().is_some_and(|token| {
                    token.value == state.token
                        && token.issued_at.elapsed() <= Duration::from_secs(600)
                })
        });
        if !valid {
            self.management = None;
            return Err(ErrorStatus::NotAllowed);
        }
        Ok(())
    }

    fn delete_credential(
        &mut self,
        params: Option<&[(Value, Value)]>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let id = management_credential_id(params)?;
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
        Ok(encode_empty_response())
    }

    fn update_user_information(
        &mut self,
        params: Option<&[(Value, Value)]>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let id = management_credential_id(params)?;
        let user = validate_management_user(params)?;
        let user_id = map_bytes(user, "id").expect("validated user ID");
        let credential_index = self
            .credentials
            .iter()
            .position(|credential| credential.discoverable && credential.id == id)
            .ok_or(ErrorStatus::NoCredentials)?;
        if self.credentials[credential_index].user_handle != user_id {
            return Err(ErrorStatus::InvalidParameter);
        }
        let previous_name = self.credentials[credential_index].user_name.clone();
        let previous_display_name = self.credentials[credential_index].user_display_name.clone();
        self.credentials[credential_index].user_name = map_text(user, "name")
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        self.credentials[credential_index].user_display_name = map_text(user, "displayName")
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        if let Err(error) = self.save_credentials() {
            self.credentials[credential_index].user_name = previous_name;
            self.credentials[credential_index].user_display_name = previous_display_name;
            return Err(error);
        }
        self.management = None;
        Ok(encode_empty_response())
    }

    fn set_pin(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        new_pin_enc: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<Vec<u8>, ErrorStatus> {
        if self.client_pin.is_some() {
            return Err(ErrorStatus::PinAuthInvalid);
        }
        if new_pin_enc.len() != 80 {
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
        Ok(encode_empty_response())
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
        if new_pin_enc.len() != 80 || pin_hash_enc.len() != 32 {
            return Err(ErrorStatus::InvalidParameter);
        }
        let (aes_key, hmac_key) = self.pin_uv_keys(key_agreement)?;
        let mut auth_message = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_message.extend_from_slice(new_pin_enc);
        auth_message.extend_from_slice(pin_hash_enc);
        verify_pin_uv_auth_param(&hmac_key, pin_uv_auth_param, &auth_message)?;
        let pin_hash = decrypt_pin_hash(&aes_key, pin_hash_enc)?;
        self.authenticate_pin(&pin_hash)?;
        let new_pin = decrypt_pin(&aes_key, new_pin_enc)?;
        validate_new_pin(&new_pin)?;

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
        self.pin_uv_auth_token = None;
        Ok(encode_empty_response())
    }

    fn get_pin_uv_auth_token(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        pin_hash_enc: &[u8],
        raw_permissions: u8,
        rp_id: Option<String>,
        allow_missing_rp_id: bool,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let permissions =
            validate_token_permissions(raw_permissions, rp_id.as_deref(), allow_missing_rp_id)?;
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
            first_used_at: None,
            user_present_until: None,
        });
        let encrypted_token = encrypt_aes(&aes_key, &token)?;
        Ok(encode_response(
            cbor!({
                2 => byte_string(encrypted_token),
            })
            .unwrap(),
        ))
    }

    fn get_pin_uv_auth_token_using_uv(
        &mut self,
        key_agreement: Option<&[(Value, Value)]>,
        raw_permissions: u8,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let permissions = validate_token_permissions(raw_permissions, rp_id.as_deref(), false)?;
        let prompt = rp_id.as_deref().map_or_else(
            || "Verify identity for a FIDO2 operation".to_owned(),
            |rp_id| format!("Verify identity for FIDO2 operations at {rp_id}"),
        );
        if !self.user_presence_approved(&prompt, "UV token issuance") {
            return Err(ErrorStatus::OperationDenied);
        }
        let (aes_key, _mac_key) = self.pin_uv_keys(key_agreement)?;
        let mut token = vec![0u8; 32];
        fill_random(&mut token);
        let issued_at = Instant::now();
        self.pin_uv_auth_token = Some(PinUvAuthToken {
            value: token.clone(),
            permissions,
            rp_id,
            issued_at,
            first_used_at: None,
            user_present_until: Some(issued_at + Duration::from_secs(30)),
        });
        let encrypted_token = encrypt_aes(&aes_key, &token)?;
        Ok(encode_response(
            cbor!({
                2 => byte_string(encrypted_token),
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
        let Some(mut updated_pin) = self.client_pin.clone() else {
            return Err(ErrorStatus::PinNotSet);
        };
        if updated_pin.retries == 0 {
            return Err(ErrorStatus::PinBlocked);
        }
        // A correct guess must not bypass the three-attempt power-cycle lock.
        if self.consecutive_pin_mismatches >= 3 {
            return Err(ErrorStatus::PinAuthBlocked);
        }

        let candidate = pin_verifier(&updated_pin.pin_salt, pin_hash);
        if !constant_time_equal(&candidate, &updated_pin.pin_verifier) {
            updated_pin.retries = updated_pin.retries.saturating_sub(1);
            let retries = updated_pin.retries;
            self.consecutive_pin_mismatches = self.consecutive_pin_mismatches.saturating_add(1);
            self.key_agreement = None;
            // Failed writes cannot restore retries within this running instance.
            self.client_pin = Some(updated_pin.clone());
            self.persist_client_pin(&updated_pin)?;
            return Err(if retries == 0 {
                ErrorStatus::PinBlocked
            } else if self.consecutive_pin_mismatches >= 3 {
                ErrorStatus::PinAuthBlocked
            } else {
                ErrorStatus::PinInvalid
            });
        }

        self.consecutive_pin_mismatches = 0;
        if updated_pin.retries != PIN_RETRIES {
            updated_pin.retries = PIN_RETRIES;
            self.persist_client_pin(&updated_pin)?;
            self.client_pin = Some(updated_pin);
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

    fn save_credentials(&self) -> Result<(), ErrorStatus> {
        let credentials: Vec<store::StoredCtap2Credential> = self
            .credentials
            .iter()
            .map(store::StoredCtap2Credential::from)
            .collect();
        store::save_ctap2_credentials_to_dir(&self.store_dir, &credentials).map_err(|error| {
            log::warn!("failed to save CTAP2 credential store: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        log::info!(
            "saved {} TPM-backed CTAP2 credentials to SQLite store {}",
            credentials.len(),
            store::credentials_database_path_in_dir(&self.store_dir).display()
        );
        Ok(())
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

    fn zero_length_pin_uv_auth(&self, prompt: &str) -> Result<Vec<u8>, ErrorStatus> {
        if !self.user_presence_approved(prompt, "authenticator selection") {
            return Err(ErrorStatus::OperationDenied);
        }
        Err(if self.client_pin.is_some() {
            ErrorStatus::PinInvalid
        } else {
            ErrorStatus::PinNotSet
        })
    }

    fn pin_uv_auth_token_has_cached_user_presence(&self) -> bool {
        self.pin_uv_auth_token.as_ref().is_some_and(|token| {
            token
                .user_present_until
                .is_some_and(|deadline| Instant::now() <= deadline)
        })
    }

    fn consume_pin_uv_auth_token_after_user_presence(&mut self) {
        if let Some(token) = &mut self.pin_uv_auth_token {
            token.permissions &= Ctap2PermissionFlags::LARGE_BLOB_WRITE;
            token.user_present_until = None;
        }
    }

    fn assertion_approved(&mut self, rp_id: &str) -> bool {
        self.user_presence_approved(
            &format!("Authenticate with passkey for {rp_id}"),
            &format!("assertion for {rp_id}"),
        )
    }

    fn user_presence_approved(&self, prompt: &str, operation: &str) -> bool {
        if self.operation_is_cancelled() {
            return false;
        }
        log::debug!("requesting approval for {operation}");
        if let Some(status) = &self.operation_status {
            status.store(2, Ordering::SeqCst);
        }
        let approved = self.approval.approve(prompt);
        if let Some(status) = &self.operation_status {
            status.store(1, Ordering::SeqCst);
        }
        approved && !self.operation_is_cancelled()
    }

    fn operation_is_cancelled(&self) -> bool {
        self.operation_cancelled
            .as_ref()
            .is_some_and(|cancelled| cancelled.load(Ordering::SeqCst))
    }

    fn validate_pin_uv_auth(
        &mut self,
        protocol: Option<i128>,
        auth_param: Option<&[u8]>,
        message: &[u8],
        permission: Ctap2PermissionFlags,
        rp_id: Option<&str>,
    ) -> Result<bool, ErrorStatus> {
        if protocol.is_none() && auth_param.is_none() {
            return Ok(false);
        }
        validate_pin_uv_protocol(protocol)?;
        let auth_param = auth_param.ok_or(ErrorStatus::MissingParameter)?;
        let Some(token) = self
            .pin_uv_auth_token
            .as_ref()
            .filter(|token| {
                token.issued_at.elapsed() <= Duration::from_secs(600)
                    && (token.first_used_at.is_some()
                        || token.issued_at.elapsed() <= Duration::from_secs(30))
            })
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
        if auth_param.len() != 32 {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        }
        let mut mac =
            HmacSha256::new_from_slice(&token.value).map_err(|_| ErrorStatus::OperationDenied)?;
        mac.update(message);
        let expected = mac.finalize().into_bytes();
        if !constant_time_equal(&expected[..auth_param.len()], auth_param) {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        }

        let current_token = self
            .pin_uv_auth_token
            .as_mut()
            .expect("validated token remains present");
        current_token.first_used_at.get_or_insert_with(Instant::now);
        if current_token.rp_id.is_none()
            && permission.intersects(
                Ctap2PermissionFlags::MAKE_CREDENTIAL | Ctap2PermissionFlags::GET_ASSERTION,
            )
        {
            current_token.rp_id = rp_id.map(str::to_owned);
        }
        Ok(true)
    }

    fn set_recovery_passphrase(
        &mut self,
        old_passphrase: Option<&str>,
        new_passphrase: &str,
    ) -> color_eyre::Result<()> {
        let config = store::load_recovery_config(&self.store_dir)?;
        let old_unlock = config
            .as_ref()
            .map(|config| {
                let passphrase = old_passphrase.ok_or_else(|| {
                    color_eyre::eyre::eyre!("provide the current recovery passphrase to change it")
                })?;
                UnlockedRecovery::unlock(config, passphrase)
            })
            .transpose()?;
        let new_unlock = UnlockedRecovery::new(new_passphrase)?;
        let mut credentials = store::load_ctap2_credentials_from_dir(&self.store_dir)?;
        let mut slots = Vec::new();
        for credential in &mut credentials {
            let Some(slot) = &mut credential.recovery else {
                continue;
            };
            let old_unlock = old_unlock.as_ref().ok_or_else(|| {
                color_eyre::eyre::eyre!("recovery slot exists without encryption configuration")
            })?;
            let policy_ref = credential
                .policy
                .as_ref()
                .and_then(|policy| policy.policy_ref.as_deref())
                .ok_or_else(|| color_eyre::eyre::eyre!("recovery credential has no policyRef"))?;
            let aad = recovery::credential_aad(&credential.id, &slot.key.public, policy_ref);
            let secret = old_unlock.decrypt(&slot.encrypted_auth, &aad)?;
            if secret.len() != 32 {
                color_eyre::eyre::bail!("invalid recovery authorization length");
            }
            slot.encrypted_auth = new_unlock.encrypt(&secret, &aad)?;
            slots.push((credential.id.clone(), slot.encrypted_auth.clone()));
        }
        store::save_recovery_configuration(&self.store_dir, &new_unlock.configuration()?, &slots)?;
        self.recovery_unlock = Some(new_unlock);
        // Registration uses this snapshot too; do not let a later save restore
        // pre-rotation ciphertext from stale in-memory credentials.
        self.credentials = credentials.into_iter().map(Credential::from).collect();
        self.cancel_pending();
        Ok(())
    }

    /// Execute a TPM command issued by the management thread.
    /// This runs on the main daemon thread which owns the TPM context.
    pub fn handle_tpm_command(&mut self, command: TpmCommand) -> color_eyre::Result<()> {
        match command {
            TpmCommand::PcrPolicyUpdate(cmd) => {
                let credentials = store::load_ctap2_credentials_from_dir(&self.store_dir)?;
                let credential = credentials
                    .iter()
                    .find(|c| c.id == cmd.credential_id)
                    .ok_or_else(|| color_eyre::eyre::eyre!("credential not found"))?;
                let policy = credential
                    .policy
                    .as_ref()
                    .ok_or_else(|| color_eyre::eyre::eyre!("credential has no PCR policy"))?;
                let policy_ref = policy
                    .policy_ref
                    .as_deref()
                    .ok_or_else(|| color_eyre::eyre::eyre!("credential has no policyRef"))?;
                let authority_name = policy.authority_name.as_deref().ok_or_else(|| {
                    color_eyre::eyre::eyre!("credential has no recovery authority")
                })?;
                let recovery = credential
                    .recovery
                    .as_ref()
                    .ok_or_else(|| color_eyre::eyre::eyre!("credential has no recovery slot"))?;
                // Never use the enrollment unlock cache for policy changes.
                let authority = recovery.unlock(&credential.id, policy_ref, &cmd.passphrase)?;
                let tpm = self
                    .ensure_tpm()
                    .ok_or_else(|| color_eyre::eyre::eyre!("TPM not available"))?;
                tpm.set_pcr_indices(&cmd.pcr_indices)
                    .wrap_err("selecting PCRs for policy update")?;
                let new_policy = tpm
                    .update_authorized_policy(&authority, authority_name, policy_ref)
                    .wrap_err("updating PCR policy via management TPM command")?;
                let stored_policy = store::StoredPcrPolicy {
                    selection: new_policy.selection,
                    digest: new_policy.digest,
                    policy_ref: new_policy.policy_ref,
                    authority_name: new_policy.authority_name,
                    authority_signature: new_policy.authority_signature,
                    policy_version: store::StoredPcrPolicy::current_version(),
                };
                let (last_used, used_count) = store::update_ctap2_policy_in_dir(
                    &self.store_dir,
                    &cmd.credential_id,
                    &stored_policy,
                )
                .wrap_err("saving PCR policy after TPM command")?;
                // A later full credential save must not restore the old policy
                // or erase token usage from this successful recovery.
                if let Some(cached) = self
                    .credentials
                    .iter_mut()
                    .find(|c| c.id == cmd.credential_id)
                {
                    cached.policy = Some(stored_policy);
                    if let Some(slot) = &mut cached.recovery {
                        slot.last_used = Some(last_used);
                        slot.used_count = used_count;
                    }
                }
                log::info!(
                    "updated PCR policy for credential {}",
                    hex::encode(&cmd.credential_id)
                );
                Ok(())
            }
            TpmCommand::SetRecoveryPassphrase {
                old_passphrase,
                new_passphrase,
            } => self.set_recovery_passphrase(
                old_passphrase.as_deref().map(String::as_str),
                &new_passphrase,
            ),
            TpmCommand::UnlockRecovery { passphrase } => {
                let config = store::load_recovery_config(&self.store_dir)?.ok_or_else(|| {
                    color_eyre::eyre::eyre!("recovery passphrase is not configured")
                })?;
                // Clear an earlier unlock on failure, rather than retaining stale state.
                self.recovery_unlock = None;
                self.recovery_unlock = Some(UnlockedRecovery::unlock(&config, &passphrase)?);
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
    SetRecoveryPassphrase {
        old_passphrase: Option<Zeroizing<String>>,
        new_passphrase: Zeroizing<String>,
    },
    UnlockRecovery {
        passphrase: Zeroizing<String>,
    },
    PcrDigestCheck(PcrDigestCheckCommand),
}

/// Data needed to update a credential's PCR policy via `policy_authorize`.
pub struct PcrPolicyUpdateCommand {
    pub credential_id: Vec<u8>,
    pub pcr_indices: Vec<u32>,
    pub passphrase: Zeroizing<String>,
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

fn get_info_response(client_pin: bool) -> Vec<u8> {
    encode_response(
        cbor!({
            1 => ["FIDO_2_1", "FIDO_2_0"],
            2 => ["credProps"],
            3 => byte_string(AAGUID.to_vec()),
            4 => {
                "plat" => false,
                "rk" => true,
                "up" => true,
                // The polkit approval prompt is this authenticator's built-in
                // user-verification method.
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
            5 => MAX_MSG_SIZE as u64,
            9 => ["usb"],
            10 => [{"type" => "public-key", "alg" => COSE_ALG_ES256}],
            13 => 4,
        })
        .unwrap(),
    )
}

fn client_pin_subcommand_name(sub_command: i128) -> &'static str {
    match sub_command {
        1 => "getPinRetries",
        2 => "getKeyAgreement",
        3 => "setPin",
        4 => "changePin",
        5 => "getPinTokenLegacy",
        6 => "getPinUvAuthTokenUsingUvWithPermissions",
        7 => "getUvRetries",
        9 => "getPinUvAuthTokenUsingPinWithPermissions",
        _ => "unknown",
    }
}

fn pin_uv_permissions(request: &[(Value, Value)]) -> Option<u8> {
    map_integer(request, 9).and_then(|value| u8::try_from(value).ok())
}

fn validate_token_permissions(
    raw_permissions: u8,
    rp_id: Option<&str>,
    allow_missing_rp_id: bool,
) -> Result<Ctap2PermissionFlags, ErrorStatus> {
    if raw_permissions == 0 {
        return Err(ErrorStatus::InvalidParameter);
    }
    let permissions = Ctap2PermissionFlags::from_bits_truncate(raw_permissions);
    if permissions.intersects(
        Ctap2PermissionFlags::BIO_ENROLLMENT
            | Ctap2PermissionFlags::LARGE_BLOB_WRITE
            | Ctap2PermissionFlags::AUTHENTICATOR_CONFIGURATION
            | Ctap2PermissionFlags::PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY,
    ) {
        return Err(ErrorStatus::UnauthorizedPermission);
    }
    if !allow_missing_rp_id
        && permissions
            .intersects(Ctap2PermissionFlags::MAKE_CREDENTIAL | Ctap2PermissionFlags::GET_ASSERTION)
        && rp_id.is_none()
    {
        return Err(ErrorStatus::MissingParameter);
    }
    Ok(permissions)
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
    const REQUIRED_KEYS: [i128; 5] = [1, 3, -1, -2, -3];
    if map.len() != REQUIRED_KEYS.len()
        || REQUIRED_KEYS.iter().any(|required| {
            map.iter()
                .filter(|(key, _)| key.as_integer().map(i128::from) == Some(*required))
                .count()
                != 1
        })
    {
        return Err(ErrorStatus::InvalidParameter);
    }
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
    if auth_param.len() != 32 {
        return Err(ErrorStatus::PinAuthInvalid);
    }
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| ErrorStatus::OperationDenied)?;
    mac.update(message);
    let expected = mac.finalize().into_bytes();
    constant_time_equal(&expected[..auth_param.len()], auth_param)
        .then_some(())
        .ok_or(ErrorStatus::PinAuthInvalid)
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
    let pin_text = std::str::from_utf8(pin).map_err(|_| ErrorStatus::PinPolicyViolation)?;
    if pin.len() > 63 || pin_text.chars().count() < 4 || pin.contains(&0) {
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

fn validate_make_credential_entities(
    rp: &[(Value, Value)],
    user: &[(Value, Value)],
) -> Result<(), ErrorStatus> {
    if map_text(rp, "id").is_none() || map_bytes(user, "id").is_none() {
        return Err(ErrorStatus::InvalidCbor);
    }
    for (map, key) in [
        (rp, "name"),
        (rp, "icon"),
        (user, "name"),
        (user, "displayName"),
        (user, "icon"),
    ] {
        if let Some(value) = map_value(map, key)
            && value.as_text().is_none()
        {
            return Err(ErrorStatus::InvalidCbor);
        }
    }
    Ok(())
}

fn validate_pub_key_cred_params(params: &[Value]) -> Result<(), ErrorStatus> {
    let mut supported_algorithm = false;
    let mut seen = Vec::new();
    for value in params {
        let Value::Map(map) = value else {
            return Err(ErrorStatus::InvalidCbor);
        };
        let credential_type = map_text(map, "type").ok_or(ErrorStatus::InvalidCbor)?;
        let algorithm = map_value(map, "alg")
            .and_then(Value::as_integer)
            .and_then(|integer| i64::try_from(integer).ok())
            .ok_or(ErrorStatus::InvalidCbor)?;
        if seen.contains(&(credential_type, algorithm)) {
            return Err(ErrorStatus::InvalidCbor);
        }
        seen.push((credential_type, algorithm));
        supported_algorithm |= credential_type == "public-key" && algorithm == COSE_ALG_ES256;
    }
    supported_algorithm
        .then_some(())
        .ok_or(ErrorStatus::UnsupportedAlgorithm)
}

fn validate_known_boolean_options(
    options: &[(Value, Value)],
    known: &[&str],
) -> Result<(), ErrorStatus> {
    for key in known {
        if let Some(value) = map_value(options, *key)
            && value.as_bool().is_none()
        {
            return Err(ErrorStatus::InvalidCbor);
        }
    }
    Ok(())
}

fn validate_make_credential_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };
    validate_known_boolean_options(options, &["rk", "up", "uv"])?;
    if map_bool(options, "up") == Some(false) {
        return Err(ErrorStatus::InvalidOption);
    }
    Ok(())
}

fn validate_get_assertion_options(options: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    let Some(options) = options else {
        return Ok(());
    };
    validate_known_boolean_options(options, &["up", "uv"])?;
    if map_value(options, "rk").is_some() {
        return Err(ErrorStatus::UnsupportedOption);
    }
    Ok(())
}

fn validate_credential_descriptor_list(
    list: Option<&[Value]>,
    reject_empty: bool,
) -> Result<(), ErrorStatus> {
    let Some(list) = list else {
        return Ok(());
    };
    if reject_empty && list.is_empty() {
        return Err(ErrorStatus::InvalidParameter);
    }

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
        if let Some(transports) = map_value(map, "transports") {
            let transports = transports.as_array().ok_or(ErrorStatus::InvalidCbor)?;
            if transports
                .iter()
                .any(|transport| transport.as_text().is_none())
            {
                return Err(ErrorStatus::InvalidCbor);
            }
        }
    }

    Ok(())
}

fn validate_cred_props_extension(extensions: Option<&[(Value, Value)]>) -> Result<(), ErrorStatus> {
    let Some(extensions) = extensions else {
        return Ok(());
    };
    if let Some(value) = map_value(extensions, "credProps")
        && value.as_bool().is_none()
    {
        return Err(ErrorStatus::InvalidCbor);
    }
    Ok(())
}

fn validate_attestation_formats(formats: Option<&[Value]>) -> Result<(), ErrorStatus> {
    let Some(formats) = formats else {
        return Ok(());
    };
    formats
        .iter()
        .all(|format| format.as_text().is_some())
        .then_some(())
        .ok_or(ErrorStatus::InvalidCbor)
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

    credential_descriptor_list_contains(allow_list, credential_id)
}

fn validate_client_data_hash(client_data_hash: &[u8]) -> Result<(), ErrorStatus> {
    if client_data_hash.len() != 32 {
        log::debug!(
            "ctap2 validation field=clientDataHash actual_len={} expected_len=32",
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
    let mut indexes: Vec<_> = credentials
        .iter()
        .enumerate()
        .filter_map(|(index, credential)| {
            if credential.rp_id != rp_id {
                return None;
            }
            let matches = match allow_list {
                Some(list) => allow_list_allows(Some(list), &credential.id),
                None => credential.discoverable,
            };
            matches.then_some(index)
        })
        .collect();
    if allow_list.is_none() {
        indexes.reverse();
    }
    indexes
}

fn credential_descriptor_list_contains(list: &[Value], credential_id: &[u8]) -> bool {
    list.iter().any(|entry| {
        let Value::Map(map) = entry else {
            return false;
        };
        map_text(map, "type") == Some("public-key") && map_bytes(map, "id") == Some(credential_id)
    })
}

fn display_rp_label(rp_name: Option<&str>, rp_id: &str) -> String {
    match rp_name {
        Some(name) if name != rp_id => format!("{name} ({rp_id})"),
        _ => rp_id.to_owned(),
    }
}

fn validate_enumerate_credentials_params(
    params: Option<&[(Value, Value)]>,
) -> Result<(), ErrorStatus> {
    let params = params.ok_or(ErrorStatus::MissingParameter)?;
    let rp_hash = map_value(params, 1).ok_or(ErrorStatus::MissingParameter)?;
    let rp_hash = rp_hash.as_bytes().ok_or(ErrorStatus::InvalidCbor)?;
    if rp_hash.len() != 32 {
        return Err(ErrorStatus::InvalidParameter);
    }
    Ok(())
}

fn management_credential_id(params: Option<&[(Value, Value)]>) -> Result<&[u8], ErrorStatus> {
    let params = params.ok_or(ErrorStatus::MissingParameter)?;
    let descriptor = map_value(params, 2).ok_or(ErrorStatus::MissingParameter)?;
    let descriptor = descriptor.as_map().ok_or(ErrorStatus::InvalidCbor)?;
    let credential_type = map_value(descriptor, "type").ok_or(ErrorStatus::MissingParameter)?;
    if credential_type.as_text() != Some("public-key") {
        return Err(ErrorStatus::InvalidCbor);
    }
    map_value(descriptor, "id")
        .ok_or(ErrorStatus::MissingParameter)?
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or(ErrorStatus::InvalidCbor)
}

fn validate_management_user(
    params: Option<&[(Value, Value)]>,
) -> Result<&[(Value, Value)], ErrorStatus> {
    let params = params.ok_or(ErrorStatus::MissingParameter)?;
    let user = map_value(params, 3).ok_or(ErrorStatus::MissingParameter)?;
    let user = user.as_map().ok_or(ErrorStatus::InvalidCbor)?;
    let id = map_value(user, "id").ok_or(ErrorStatus::MissingParameter)?;
    if id.as_bytes().is_none() {
        return Err(ErrorStatus::InvalidCbor);
    }
    for key in ["name", "displayName"] {
        if map_value(user, key).is_some_and(|value| value.as_text().is_none()) {
            return Err(ErrorStatus::InvalidCbor);
        }
    }
    Ok(user)
}

fn credential_user_entity(credential: &Credential, include_names: bool) -> Value {
    match (
        include_names
            .then_some(credential.user_name.as_deref())
            .flatten(),
        include_names
            .then_some(credential.user_display_name.as_deref())
            .flatten(),
    ) {
        (Some(name), Some(display_name)) => cbor!({
            "id" => byte_string(credential.user_handle.clone()),
            "name" => name,
            "displayName" => display_name,
        }),
        (Some(name), None) => cbor!({
            "id" => byte_string(credential.user_handle.clone()),
            "name" => name,
        }),
        (None, Some(display_name)) => cbor!({
            "id" => byte_string(credential.user_handle.clone()),
            "displayName" => display_name,
        }),
        (None, None) => cbor!({ "id" => byte_string(credential.user_handle.clone()) }),
    }
    .expect("credential user entity")
}

fn encode_rp_response(credential: &Credential, total: Option<usize>) -> Vec<u8> {
    let response = match total {
        Some(total) => cbor!({
            3 => { "id" => credential.rp_id.as_str(), "name" => credential.rp_id.as_str() },
            4 => byte_string(Sha256::digest(credential.rp_id.as_bytes()).to_vec()),
            5 => total as u64,
        }),
        None => cbor!({
            3 => { "id" => credential.rp_id.as_str(), "name" => credential.rp_id.as_str() },
            4 => byte_string(Sha256::digest(credential.rp_id.as_bytes()).to_vec()),
        }),
    }
    .expect("credential-management RP response");
    encode_response(response)
}

fn encode_credential_management_response(credential: &Credential, total: Option<usize>) -> Vec<u8> {
    let user = credential_user_entity(credential, true);
    let public_key = cose_credential_public_key(&credential.key);
    let response = match total {
        Some(total) => cbor!({
            6 => user,
            7 => { "type" => "public-key", "id" => byte_string(credential.id.clone()) },
            8 => public_key,
            9 => total as u64,
        }),
        None => cbor!({
            6 => user,
            7 => { "type" => "public-key", "id" => byte_string(credential.id.clone()) },
            8 => public_key,
        }),
    }
    .expect("credential-management credential response");
    encode_response(response)
}

fn encode_assertion_response(
    credential_id: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    user: Option<Value>,
    total_credentials: usize,
) -> Vec<u8> {
    let descriptor = cbor!({
        "type" => "public-key",
        "id" => byte_string(credential_id),
    })
    .expect("assertion credential descriptor");
    let mut response = cbor_map_entries(
        cbor!({
            1 => descriptor,
            2 => byte_string(auth_data),
            3 => byte_string(signature),
        })
        .expect("assertion response"),
    );
    if let Some(user) = user {
        response.extend(cbor_map_entries(
            cbor!({ 4 => user }).expect("assertion user"),
        ));
    }
    if total_credentials > 1 {
        response.extend(cbor_map_entries(
            cbor!({ 5 => total_credentials as u64 }).expect("assertion credential count"),
        ));
    }
    encode_response(map(response))
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
    let authority_key = authority.map(store::StoredRecoverySlot::authority);
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

#[cfg(test)]
fn management_auth_message(sub_command: i128, params: Option<&[(Value, Value)]>) -> Vec<u8> {
    let mut encoded = vec![sub_command as u8];
    if let Some(params) = params {
        let value = canonicalize_value(map(params.to_vec()));
        ciborium::into_writer(&value, &mut encoded).expect("serializing management parameters");
    }
    encoded
}

#[cfg(test)]
mod cbor_compliance_tests;
#[cfg(test)]
mod pin_compliance_tests;
#[cfg(test)]
mod tests;
