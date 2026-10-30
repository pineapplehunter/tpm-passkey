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
    approval, credential::Credential, management::ManagementError, migration_crypto, store, tpm,
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

const PIN_RETRIES: u32 = 8;
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
    credentials: Vec<Credential>,
    credential_load_failed: bool,
    pending_assertion: Option<PendingAssertion>,
    client_pin: Option<ClientPinState>,
    client_pin_load_failed: bool,
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
    protocol: u64,
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

#[derive(Clone)]
struct PendingAssertion {
    rp_id: String,
    client_data_hash: Vec<u8>,
    credential_indexes: Vec<usize>,
    total_credentials: usize,
    created_at: Instant,
    token: Option<Vec<u8>>,
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
        let (credentials, credential_load_failed) =
            match Self::load_credentials_from_disk(&store_dir) {
                Ok(credentials) => (credentials, false),
                Err(error) => {
                    log::warn!(
                        "failed to load credentials; blocking credential operations: {error:?}"
                    );
                    (Vec::new(), true)
                }
            };
        log::info!("loaded {} TPM-backed CTAP2 credentials", credentials.len());
        let mut client_pin_load_failed = false;
        let client_pin = match store::load_client_pin_state_from_dir(&store_dir) {
            Ok(Some(state)) => Some(ClientPinState {
                pin_salt: state.pin_salt,
                pin_verifier: state.pin_verifier,
                retries: state.retries,
            }),
            Ok(None) => None,
            Err(error) => {
                log::warn!(
                    "failed to load clientPIN state; blocking credential operations: {error:?}"
                );
                client_pin_load_failed = true;
                None
            }
        };

        Self {
            store_dir,
            tpm_path,
            tpm,
            approval,
            credentials,
            credential_load_failed,
            pending_assertion: None,
            client_pin,
            client_pin_load_failed,
            key_agreement: Some(EphemeralSecret::generate()),
            pin_uv_auth_token: None,
            consecutive_pin_mismatches: 0,
            management: None,
            powered_up_at: Instant::now(),
            operation_cancelled: None,
            operation_status: None,
        }
    }

    fn load_credentials_from_disk(store_dir: &PathBuf) -> color_eyre::Result<Vec<Credential>> {
        store::load_ctap2_credentials_from_dir(store_dir)
            .map(|credentials| credentials.into_iter().map(Credential::from).collect())
    }

    fn reload_credentials(&mut self) -> Result<(), ErrorStatus> {
        match Self::load_credentials_from_disk(&self.store_dir) {
            Ok(credentials) => {
                self.credentials = credentials;
                Ok(())
            }
            Err(error) => {
                log::warn!("credential reload failed; blocking credential operations: {error:?}");
                self.credential_load_failed = true;
                self.cancel_pending();
                Err(ErrorStatus::IntegrityFailure)
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

        if command != Ctap2Command::GetNextAssertion {
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

        // Unreadable persistent state is not an empty/unconfigured authenticator.
        // Keep discovery/reset available, but never permit a protection downgrade.
        if (self.client_pin_load_failed || self.credential_load_failed)
            && matches!(
                command,
                Ctap2Command::ClientPin
                    | Ctap2Command::MakeCredential
                    | Ctap2Command::GetAssertion
                    | Ctap2Command::GetNextAssertion
                    | Ctap2Command::CredentialManagement
            )
        {
            return error_response(ErrorStatus::IntegrityFailure);
        }

        let result = match command {
            Ctap2Command::GetInfo => body
                .is_empty()
                .then(|| {
                    get_info_response(self.client_pin.is_some() || self.client_pin_load_failed)
                })
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
        self.key_agreement = Some(EphemeralSecret::generate());
    }

    /// authenticatorReset (0x07): factory-resets the authenticator, deleting all
    /// credentials and clearing the configured PIN. CTAP2.2 §6.6 requires user
    /// presence (and, when set, alwaysUv) before performing the reset.
    fn reset(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        if self.powered_up_at.elapsed() > Duration::from_secs(10) {
            return Err(ErrorStatus::NotAllowed);
        }
        self.user_presence_approved(
            &approval::context("reset", ""),
            ErrorStatus::UserActionTimeout,
        )?;
        if self.operation_is_cancelled() {
            return Err(ErrorStatus::KeepaliveCancel);
        }
        store::reset_authenticator_state_from_dir(&self.store_dir).map_err(|error| {
            log::warn!("failed to persist authenticator reset: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        self.credentials.clear();
        self.credential_load_failed = false;
        self.client_pin = None;
        self.client_pin_load_failed = false;
        self.consecutive_pin_mismatches = 0;
        self.key_agreement = Some(EphemeralSecret::generate());
        self.pin_uv_auth_token = None;
        self.pending_assertion = None;
        self.management = None;
        Ok(vec![0x00])
    }

    /// authenticatorSelection (0x0B): returns success once
    /// the user has given consent. CTAP2.2 §6.9. The actual user gesture is
    /// collected by the transport/UI; here we just confirm approval.
    fn selection(&mut self) -> Result<Vec<u8>, ErrorStatus> {
        self.user_presence_approved(
            &approval::context("selection", ""),
            ErrorStatus::UserActionTimeout,
        )?;
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

        let client_data_hash = optional_bytes(&request, 1)
            .map_err(|_| ErrorStatus::CborUnexpectedType)?
            .ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let rp = optional_map(&request, 2)
            .map_err(|_| ErrorStatus::CborUnexpectedType)?
            .ok_or(ErrorStatus::MissingParameter)?;
        let user = optional_map(&request, 3)
            .map_err(|_| ErrorStatus::CborUnexpectedType)?
            .ok_or(ErrorStatus::MissingParameter)?;
        validate_make_credential_entities(rp, user)?;
        let params = optional_array(&request, 4)
            .map_err(|_| ErrorStatus::CborUnexpectedType)?
            .ok_or(ErrorStatus::MissingParameter)?;
        validate_pub_key_cred_params(params)?;
        let exclude_list = optional_array(&request, 5)?;
        // No authenticator extensions are implemented. Unknown inputs, including
        // the client-only credProps extension, must not produce signed outputs.
        let _extensions = optional_map(&request, 6)?;
        validate_attestation_formats(optional_array(&request, 11)?)?;
        if map_value(&request, 10).is_some() {
            return Err(ErrorStatus::InvalidParameter);
        }

        if self.tpm_path.is_some() {
            self.reload_credentials()?;
        }
        let rp_id = map_text(rp, "id").ok_or(ErrorStatus::MissingParameter)?;
        let rp_name = map_text(rp, "name");
        let user_handle = map_bytes(user, "id").ok_or(ErrorStatus::MissingParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");
        let pin_uv_auth_param = optional_bytes(&request, 8)?;
        let pin_uv_auth_protocol = optional_integer(&request, 9)?;
        if pin_uv_auth_param == Some(&[]) {
            return self.zero_length_pin_uv_auth();
        }
        let pin_uv_auth_present = pin_uv_auth_param.is_some();
        let user_verified = self.validate_pin_uv_auth(
            pin_uv_auth_protocol.filter(|_| pin_uv_auth_present),
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
        if !pin_uv_auth_present
            && options.is_some_and(|options| map_bool(options, "uv") == Some(true))
        {
            return Err(ErrorStatus::InvalidOption);
        }
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
        if discoverable && self.client_pin.is_some() && !user_verified {
            return Err(ErrorStatus::PuatRequired);
        }

        if self.operation_is_cancelled() {
            log::error!("operation cancelled before registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        let cached_user_presence =
            user_verified && self.pin_uv_auth_token_has_cached_user_presence();
        // §6.1.2 step 12 precedes the normal UP/token-consumption step.
        // Exclusion is reported even if the presence wait times out, without
        // consuming the token's permissions or cached user presence.
        if excluded_credential_exists(&self.credentials, rp_id, exclude_list) {
            if !cached_user_presence {
                let result = self.user_presence_approved(
                    &approval::context("register", rp_id),
                    ErrorStatus::OperationDenied,
                );
                if result == Err(ErrorStatus::KeepaliveCancel) {
                    return Err(ErrorStatus::KeepaliveCancel);
                }
            }
            return Err(ErrorStatus::CredentialExcluded);
        }
        if !cached_user_presence {
            let mut context = approval::context("register", rp_id);
            context.rp_name = rp_name.unwrap_or("").to_owned();
            context.account_name = user_name.or(user_display_name).unwrap_or("").to_owned();
            context.account_id = hex::encode(user_handle);
            self.user_presence_approved(&context, ErrorStatus::OperationDenied)?;
        }
        self.consume_pin_uv_auth_token_after_user_presence();

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

        if self.operation_is_cancelled() {
            log::error!("operation cancelled during registration approval");
            return Err(ErrorStatus::OperationDenied);
        }

        let _mutation_guard = store::try_credential_mutation_guard().map_err(|error| {
            log::warn!("failed to serialize registration with management updates: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        let (pcr_indices, migration_config) = self.pcr_enrollment()?;
        let Some(tpm) = self.ensure_tpm() else {
            log::warn!("cannot create CTAP2 credential without TPM context");
            return Err(ErrorStatus::OperationDenied);
        };
        let mut credential_id = vec![0u8; 32];
        fill_random(&mut credential_id);
        // Every credential is protected by PolicyAuthorize, including the
        // PCR-disabled baseline. Enrollment never unlocks a passphrase: only
        // the persistent public migration key is needed for the envelope.
        let (policy, authority) = (|| -> color_eyre::Result<_> {
            let authority = tpm.create_migration_authority()?;
            let policy_ref = tpm::credential_policy_ref(&credential_id);
            let policy = if let Some(indices) = &pcr_indices {
                tpm.set_pcr_indices(indices)?;
                let approved = tpm.create_secure_boot_policy()?;
                tpm.create_authorized_policy(&approved, &authority, &policy_ref)?
            } else {
                tpm.create_authorized_baseline_policy(&authority, &policy_ref)?
            };
            Ok((policy, authority))
        })()
        .map_err(|error| {
            log::warn!("failed to create policy-authorized credential: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        let key = match tpm.create_credential_key_with_policy(Some(&policy)) {
            Ok(credential) => credential,
            Err(error) => {
                log::warn!("failed to create TPM-backed CTAP2 credential key: {error:?}");
                return Err(ErrorStatus::OperationDenied);
            }
        };
        log::info!("created TPM-backed CTAP2 credential key");
        let policy_ref = policy.policy_ref.as_deref().expect("authorized policyRef");
        let context =
            migration_crypto::authorization_context(&credential_id, &authority.public, policy_ref)
                .map_err(|error| {
                    log::warn!("invalid migration envelope context: {error}");
                    ErrorStatus::OperationDenied
                })?;
        let encrypted_auth = migration_crypto::encrypt(
            migration_config.public_key(),
            &context,
            authority
                .auth_value
                .as_ref()
                .expect("random migration authorization"),
        )
        .map_err(|error| {
            log::warn!("failed to encrypt migration authorization: {error}");
            ErrorStatus::OperationDenied
        })?;
        let migration_authority = Some(store::StoredMigrationAuthority {
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
        });
        let public_key = cose_credential_public_key(&key);

        let auth_data = make_auth_data(
            rp_id,
            0x41 | if user_verified { 0x04 } else { 0 },
            0,
            Some((&credential_id, &public_key)),
            None,
        );
        // TPM commands cannot be preempted, but cancellation observed after
        // key creation must not replace/persist an existing passkey.
        if self.operation_is_cancelled() {
            return Err(ErrorStatus::KeepaliveCancel);
        }
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
            migration_authority,
            sign_count: 0,
        });
        if self.operation_is_cancelled() {
            self.credentials = previous_credentials;
            return Err(ErrorStatus::KeepaliveCancel);
        }
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

        let rp_id = map_value(&request, 1)
            .ok_or(ErrorStatus::MissingParameter)?
            .as_text()
            .ok_or(ErrorStatus::CborUnexpectedType)?;
        let client_data_hash = optional_bytes(&request, 2)
            .map_err(|_| ErrorStatus::CborUnexpectedType)?
            .ok_or(ErrorStatus::MissingParameter)?;
        validate_client_data_hash(client_data_hash)?;
        let pin_uv_auth_param = optional_bytes(&request, 6)?;
        let pin_uv_auth_protocol = optional_integer(&request, 7)?;
        if pin_uv_auth_param == Some(&[]) {
            return self.zero_length_pin_uv_auth();
        }
        let pin_uv_auth_present = pin_uv_auth_param.is_some();
        let user_verified = self.validate_pin_uv_auth(
            pin_uv_auth_protocol.filter(|_| pin_uv_auth_present),
            pin_uv_auth_param,
            client_data_hash,
            Ctap2PermissionFlags::GET_ASSERTION,
            Some(rp_id),
        )?;
        let allow_list = optional_array(&request, 3)?;
        let _extensions = optional_map(&request, 4)?;
        let options = optional_map(&request, 5)?;
        validate_get_assertion_options(options)?;
        if !pin_uv_auth_present
            && options.is_some_and(|options| map_bool(options, "uv") == Some(true))
        {
            return Err(ErrorStatus::InvalidOption);
        }
        let user_presence = options.and_then(|options| map_bool(options, "up")) != Some(false);
        validate_credential_descriptor_list(allow_list, true)?;

        // Reload credentials from disk when running as daemon (tpm_path is set)
        // to pick up management-side modifications (e.g., migrate-pcr-reference).
        if self.tpm_path.is_some() {
            self.reload_credentials()?;
        }
        let credential_indexes = matching_credential_indexes(&self.credentials, rp_id, allow_list);
        let Some((&credential_index, remaining_indexes)) = credential_indexes.split_first() else {
            return Err(ErrorStatus::NoCredentials);
        };

        let cached_user_presence =
            user_verified && self.pin_uv_auth_token_has_cached_user_presence();
        if user_presence && !cached_user_presence {
            self.assertion_approved(rp_id, credential_indexes.len())?;
        }
        if user_presence {
            self.consume_pin_uv_auth_token_after_user_presence();
        }

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

            // §§6.1.3/6.2 require the user handle for discoverable credentials,
            // even when selected by an allowList. Keep identifying names out of
            // allow-list responses, where account selection is unnecessary.
            let user = (credential.discoverable || allow_list.is_none())
                .then(|| credential_user_entity(credential, user_verified && allow_list.is_none()));

            (
                auth_data,
                user,
                credential.id.clone(),
                credential.key.clone(),
                credential.policy.clone(),
                credential.migration_authority.clone(),
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
        self.pending_assertion = if remaining_indexes.is_empty() || allow_list.is_some() {
            None
        } else {
            Some(PendingAssertion {
                rp_id: rp_id.to_owned(),
                client_data_hash: client_data_hash.to_vec(),
                credential_indexes: remaining_indexes.to_vec(),
                total_credentials: credential_indexes.len(),
                created_at: Instant::now(),
                token: self
                    .pin_uv_auth_token
                    .as_ref()
                    .filter(|_| user_verified)
                    .map(|token| token.value.clone()),
                user_presence,
                user_verified,
            })
        };
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

        let Some(pending) = self.pending_assertion.clone() else {
            return Err(ErrorStatus::NotAllowed);
        };

        if pending.created_at.elapsed() > Duration::from_secs(30)
            || pending.token.as_ref().is_some_and(|expected| {
                !self.pin_uv_auth_token.as_ref().is_some_and(|token| {
                    &token.value == expected
                        && token.issued_at.elapsed() <= Duration::from_secs(600)
                })
            })
        {
            self.pending_assertion = None;
            return Err(ErrorStatus::NotAllowed);
        }

        let Some((&credential_index, remaining_indexes)) = pending.credential_indexes.split_first()
        else {
            self.pending_assertion = None;
            return Err(ErrorStatus::NotAllowed);
        };
        let Some(credential) = self.credentials.get(credential_index) else {
            self.pending_assertion = None;
            return Err(ErrorStatus::NotAllowed);
        };
        if credential.rp_id != pending.rp_id
            || pending.total_credentials < pending.credential_indexes.len() + 1
        {
            self.pending_assertion = None;
            return Err(ErrorStatus::NotAllowed);
        }
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
        let credential_authority = credential.migration_authority.clone();
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
        self.pending_assertion = if remaining_indexes.is_empty() {
            None
        } else {
            Some(PendingAssertion {
                credential_indexes: remaining_indexes.to_vec(),
                created_at: Instant::now(),
                ..pending
            })
        };

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
        let wrong_type = |_| ErrorStatus::CborUnexpectedType;
        let unsigned = |key| {
            optional_integer(&request, key)
                .map_err(wrong_type)?
                .map(|value| u64::try_from(value).map_err(|_| ErrorStatus::CborUnexpectedType))
                .transpose()
        };
        let protocol = unsigned(1)?.map(i128::from);
        let sub_command = i128::from(unsigned(2)?.ok_or(ErrorStatus::MissingParameter)?);
        let key_agreement = optional_map(&request, 3).map_err(wrong_type)?;
        let auth_param = optional_bytes(&request, 4).map_err(wrong_type)?;
        let new_pin_enc = optional_bytes(&request, 5).map_err(wrong_type)?;
        let pin_hash_enc = optional_bytes(&request, 6).map_err(wrong_type)?;
        let permissions = unsigned(9)?;
        if permissions == Some(0) {
            return Err(ErrorStatus::InvalidParameter);
        }
        let rp_id = match map_value(&request, 10) {
            Some(Value::Text(value)) => Some(value.clone()),
            Some(_) => return Err(ErrorStatus::CborUnexpectedType),
            None => None,
        };
        if matches!(sub_command, 6 | 7) {
            // Host approval is user presence, never built-in user verification.
            return Err(ErrorStatus::InvalidSubcommand);
        }
        if !matches!(sub_command, 1 | 2 | 3 | 4 | 5 | 9) {
            return Err(ErrorStatus::InvalidSubcommand);
        }
        if sub_command == 1 {
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
        let protocol =
            u64::try_from(protocol.unwrap_or(2)).map_err(|_| ErrorStatus::InvalidParameter)?;

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
            2 => Ok(key_agreement_response(
                self.key_agreement
                    .as_ref()
                    .expect("initialized key agreement"),
            )),
            3 => self.set_pin(
                protocol,
                key_agreement,
                new_pin_enc.ok_or(ErrorStatus::MissingParameter)?,
                auth_param.ok_or(ErrorStatus::MissingParameter)?,
            ),
            4 => self.change_pin(
                protocol,
                key_agreement,
                new_pin_enc.ok_or(ErrorStatus::MissingParameter)?,
                pin_hash_enc.ok_or(ErrorStatus::MissingParameter)?,
                auth_param.ok_or(ErrorStatus::MissingParameter)?,
            ),
            5 => {
                if map_value(&request, 9).is_some() || map_value(&request, 10).is_some() {
                    return Err(ErrorStatus::InvalidParameter);
                }
                self.get_pin_uv_auth_token(
                    protocol,
                    key_agreement,
                    pin_hash_enc.ok_or(ErrorStatus::MissingParameter)?,
                    0x03,
                    None,
                    true,
                )
            }
            9 => self.get_pin_uv_auth_token(
                protocol,
                key_agreement,
                pin_hash_enc.ok_or(ErrorStatus::MissingParameter)?,
                permissions.ok_or(ErrorStatus::MissingParameter)?,
                rp_id,
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
        if self.tpm_path.is_some() {
            self.reload_credentials()?;
        }
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
        protocol: u64,
        key_agreement: Option<&[(Value, Value)]>,
        new_pin_enc: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<Vec<u8>, ErrorStatus> {
        if self.client_pin.is_some() {
            return Err(ErrorStatus::PinAuthInvalid);
        }
        let (aes_key, hmac_key) = self.pin_uv_keys(key_agreement, protocol)?;
        verify_pin_uv_auth_param_protocol(protocol, &hmac_key, pin_uv_auth_param, new_pin_enc)?;
        Self::validate_new_pin_ciphertext(protocol, new_pin_enc)?;
        let new_pin = decrypt_pin(protocol, &aes_key, new_pin_enc)?;
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
        protocol: u64,
        key_agreement: Option<&[(Value, Value)]>,
        new_pin_enc: &[u8],
        pin_hash_enc: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<Vec<u8>, ErrorStatus> {
        let key_agreement = key_agreement.ok_or(ErrorStatus::MissingParameter)?;
        self.check_pin_attempt()?;
        let (aes_key, hmac_key) = self.pin_uv_keys(Some(key_agreement), protocol)?;
        let mut auth_message = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_message.extend_from_slice(new_pin_enc);
        auth_message.extend_from_slice(pin_hash_enc);
        verify_pin_uv_auth_param_protocol(protocol, &hmac_key, pin_uv_auth_param, &auth_message)?;
        self.authenticate_pin_attempt(|| decrypt_pin_hash(protocol, &aes_key, pin_hash_enc))?;
        Self::validate_new_pin_ciphertext(protocol, new_pin_enc)?;
        let new_pin = decrypt_pin(protocol, &aes_key, new_pin_enc)?;
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
        protocol: u64,
        key_agreement: Option<&[(Value, Value)]>,
        pin_hash_enc: &[u8],
        raw_permissions: u64,
        rp_id: Option<String>,
        allow_missing_rp_id: bool,
    ) -> Result<Vec<u8>, ErrorStatus> {
        let key_agreement = key_agreement.ok_or(ErrorStatus::MissingParameter)?;
        let permissions =
            validate_token_permissions(raw_permissions, rp_id.as_deref(), allow_missing_rp_id)?;
        self.check_pin_attempt()?;
        let (aes_key, _mac_key) = self.pin_uv_keys(Some(key_agreement), protocol)?;
        self.authenticate_pin_attempt(|| decrypt_pin_hash(protocol, &aes_key, pin_hash_enc))?;

        let mut token = vec![0u8; 32];
        fill_random(&mut token);
        self.pin_uv_auth_token = Some(PinUvAuthToken {
            protocol,
            value: token.clone(),
            permissions,
            rp_id,
            issued_at: Instant::now(),
            first_used_at: None,
            user_present_until: None,
        });
        let encrypted_token = encrypt_aes_protocol(protocol, &aes_key, &token)?;
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
        protocol: u64,
    ) -> Result<([u8; 32], [u8; 32]), ErrorStatus> {
        let client_key = key_agreement.ok_or(ErrorStatus::MissingParameter)?;
        let client_key = parse_key_agreement(client_key)?;
        let secret = self
            .key_agreement
            .as_ref()
            .ok_or(ErrorStatus::InvalidCommand)?
            .diffie_hellman(&client_key);
        derive_pin_uv_keys(protocol, secret.raw_secret_bytes().as_slice())
            .map_err(|_| ErrorStatus::OperationDenied)
    }

    // AES-CBC has no padding here: ciphertext size determines plaintext size.
    // Check only after MAC verification (and old-PIN verification for changePIN).
    fn validate_new_pin_ciphertext(protocol: u64, ciphertext: &[u8]) -> Result<(), ErrorStatus> {
        if ciphertext.is_empty()
            || !ciphertext.len().is_multiple_of(16)
            || (protocol == 2 && ciphertext.len() < 32)
        {
            return Err(ErrorStatus::PinAuthInvalid);
        }
        if ciphertext.len() != if protocol == 1 { 64 } else { 80 } {
            return Err(ErrorStatus::InvalidParameter);
        }
        Ok(())
    }

    fn check_pin_attempt(&self) -> Result<(), ErrorStatus> {
        if self.client_pin_load_failed {
            return Err(ErrorStatus::OperationDenied);
        }
        let pin = self.client_pin.as_ref().ok_or(ErrorStatus::PinNotSet)?;
        if pin.retries == 0 {
            return Err(ErrorStatus::PinBlocked);
        }
        // A correct guess must not bypass the three-attempt power-cycle lock.
        if self.consecutive_pin_mismatches >= 3 {
            return Err(ErrorStatus::PinAuthBlocked);
        }
        Ok(())
    }

    #[cfg(test)]
    fn authenticate_pin(&mut self, pin_hash: &[u8]) -> Result<(), ErrorStatus> {
        if pin_hash.len() != 16 {
            return Err(ErrorStatus::InvalidParameter);
        }
        self.authenticate_pin_attempt(|| Ok(pin_hash.to_vec()))
    }

    fn authenticate_pin_attempt(
        &mut self,
        decrypt: impl FnOnce() -> Result<Vec<u8>, ErrorStatus>,
    ) -> Result<(), ErrorStatus> {
        self.check_pin_attempt()?;
        let mut updated_pin = self.client_pin.clone().expect("checked configured PIN");
        updated_pin.retries -= 1;
        // Persist the charge before decryption/verification. If persistence is
        // uncertain, latch the running instance closed, without restoring retries.
        self.client_pin = Some(updated_pin.clone());
        if let Err(error) = self.persist_client_pin(&updated_pin) {
            self.client_pin_load_failed = true;
            return Err(error);
        }
        let matches = decrypt().is_ok_and(|pin_hash| {
            pin_hash.len() == 16
                && constant_time_equal(
                    &pin_verifier(&updated_pin.pin_salt, &pin_hash),
                    &updated_pin.pin_verifier,
                )
        });
        if !matches {
            self.consecutive_pin_mismatches = self.consecutive_pin_mismatches.saturating_add(1);
            self.key_agreement = Some(EphemeralSecret::generate());
            return Err(if updated_pin.retries == 0 {
                ErrorStatus::PinBlocked
            } else if self.consecutive_pin_mismatches >= 3 {
                ErrorStatus::PinAuthBlocked
            } else {
                ErrorStatus::PinInvalid
            });
        }

        updated_pin.retries = PIN_RETRIES;
        if let Err(error) = self.persist_client_pin(&updated_pin) {
            self.client_pin_load_failed = true;
            return Err(error);
        }
        self.client_pin = Some(updated_pin);
        self.consecutive_pin_mismatches = 0;
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

    /// Snapshot only the defaults for this new credential. Existing credential
    /// policies are never inferred from or rewritten by enrollment settings.
    fn pcr_enrollment(
        &self,
    ) -> Result<(Option<Vec<u32>>, migration_crypto::MigrationConfig), ErrorStatus> {
        let indices = store::load_default_pcr_policy(&self.store_dir).map_err(|error| {
            log::warn!("failed to load default migration policy: {error:?}");
            ErrorStatus::OperationDenied
        })?;
        let config = store::load_migration_config(&self.store_dir)
            .map_err(|error| {
                log::warn!("migration configuration authentication failed closed: {error:?}");
                ErrorStatus::OperationDenied
            })?
            .ok_or_else(|| {
                log::warn!("migration setup is required before credential registration");
                ErrorStatus::OperationDenied
            })?;
        Ok((indices, config))
    }

    fn ensure_tpm(&mut self) -> Option<&mut tpm::Tpm> {
        if self.tpm.is_none() {
            let path = self.tpm_path.clone()?;
            for attempt in 0..100 {
                // Opening a context does not bind keys. Each operation selects
                // the PCRs from its own explicit/stored policy when needed.
                match tpm::Tpm::open(&path, None) {
                    Ok(tpm) => {
                        log::info!("TPM context opened");
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

    fn zero_length_pin_uv_auth(&self) -> Result<Vec<u8>, ErrorStatus> {
        self.user_presence_approved(
            &approval::context("selection", ""),
            ErrorStatus::OperationDenied,
        )?;
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

    fn assertion_approved(
        &mut self,
        rp_id: &str,
        candidate_count: usize,
    ) -> Result<(), ErrorStatus> {
        let mut context = approval::context("login", rp_id);
        context.credential_count = u32::try_from(candidate_count).unwrap_or(u32::MAX);
        // Consent is for the RP and candidate set, not an invented account choice.
        self.user_presence_approved(&context, ErrorStatus::OperationDenied)
    }

    fn user_presence_approved(
        &self,
        context: &tpm_passkey_protocol::ApprovalContext,
        timeout_error: ErrorStatus,
    ) -> Result<(), ErrorStatus> {
        if self.operation_is_cancelled() {
            return Err(ErrorStatus::KeepaliveCancel);
        }
        log::debug!("requesting approval for {}", context.operation);
        if let Some(status) = &self.operation_status {
            status.store(2, Ordering::SeqCst);
        }
        let control = approval::ApprovalControl::new(
            self.operation_cancelled.clone(),
            Instant::now() + approval::DEFAULT_APPROVAL_TIMEOUT,
        );
        let outcome = self.approval.approve_context_controlled(context, &control);
        if let Some(status) = &self.operation_status {
            status.store(1, Ordering::SeqCst);
        }
        log::debug!("approval for {}: {outcome:?}", context.operation);
        if self.operation_is_cancelled() {
            return Err(ErrorStatus::KeepaliveCancel);
        }
        match outcome {
            approval::ApprovalOutcome::Approved => Ok(()),
            approval::ApprovalOutcome::Cancelled => Err(ErrorStatus::KeepaliveCancel),
            approval::ApprovalOutcome::Denied => Err(ErrorStatus::OperationDenied),
            // §6.1.2/§6.2.2 UP timeout: OPERATION_DENIED. §6.6/§6.9 timeout:
            // USER_ACTION_TIMEOUT. The caller selects its normative status.
            approval::ApprovalOutcome::TimedOut => Err(timeout_error),
        }
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
        if token.protocol != u64::try_from(protocol.unwrap_or_default()).unwrap_or_default()
            || !token.permissions.contains(permission)
            || token
                .rp_id
                .as_deref()
                .is_some_and(|token_rp_id| Some(token_rp_id) != rp_id)
        {
            self.pin_uv_auth_token = None;
            return Err(ErrorStatus::PinAuthInvalid);
        }
        if auth_param.len() != if token.protocol == 1 { 16 } else { 32 } {
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

    fn set_migration_passphrase(
        &mut self,
        old_passphrase: Option<&str>,
        new_passphrase: &str,
    ) -> color_eyre::Result<()> {
        let config =
            store::load_migration_config(&self.store_dir)?.ok_or(ManagementError::SetupRequired)?;
        let old_passphrase = old_passphrase.ok_or(ManagementError::Authentication)?;
        let changed = migration_crypto::change_passphrase(&config, old_passphrase, new_passphrase)
            .map_err(|_| ManagementError::Authentication)?;
        // Envelopes encrypt only the random authorization values to the public
        // key, so rotating the private-key wrapping phrase leaves them intact.
        store::save_migration_config(&self.store_dir, &changed)?;
        self.cancel_pending();
        Ok(())
    }

    /// Execute a TPM command issued by the management thread.
    /// This runs on the main daemon thread which owns the TPM context.
    pub fn handle_tpm_command(&mut self, command: TpmCommand) -> color_eyre::Result<()> {
        match command {
            TpmCommand::BeforeDeadline { deadline, command } => {
                if Instant::now() >= deadline {
                    return Err(ManagementError::Timeout.into());
                }
                self.handle_tpm_command(*command)
            }
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
                    color_eyre::eyre::eyre!("credential has no migration authority")
                })?;
                let migration = credential
                    .migration_authority
                    .as_ref()
                    .ok_or_else(|| color_eyre::eyre::eyre!("credential has no migration slot"))?;
                // Never use the enrollment unlock cache for policy changes.
                let config = store::load_migration_config(&self.store_dir)?
                    .ok_or(ManagementError::SetupRequired)?;
                let authority =
                    migration.unlock(&credential.id, policy_ref, &config, &cmd.passphrase)?;
                let tpm = self
                    .ensure_tpm()
                    .ok_or_else(|| color_eyre::eyre::eyre!("TPM not available"))?;
                let new_policy = if let Some(indices) = &cmd.pcr_indices {
                    tpm.set_pcr_indices(indices)
                        .wrap_err("selecting PCRs for policy update")?;
                    tpm.update_authorized_policy(&authority, authority_name, policy_ref)
                        .wrap_err("updating PCR policy via management TPM command")?
                } else {
                    tpm.create_authorized_baseline_policy(&authority, policy_ref)
                        .wrap_err("disabling PCR binding via authorized baseline")?
                };
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
                // or erase token usage from this successful migration.
                if let Some(cached) = self
                    .credentials
                    .iter_mut()
                    .find(|c| c.id == cmd.credential_id)
                {
                    cached.policy = Some(stored_policy);
                    if let Some(slot) = &mut cached.migration_authority {
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
            TpmCommand::SetMigrationPassphrase {
                old_passphrase,
                new_passphrase,
            } => self.set_migration_passphrase(
                old_passphrase.as_deref().map(String::as_str),
                &new_passphrase,
            ),
            TpmCommand::VerifyMigrationPassphrase { passphrase } => {
                let config = store::load_migration_config(&self.store_dir)?
                    .ok_or(ManagementError::SetupRequired)?;
                migration_crypto::change_passphrase(&config, &passphrase, &passphrase)
                    .map_err(|_| ManagementError::Authentication)?;
                // Public-key enrollment does not require retaining an unlocked
                // private key in the authenticator process.
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
    /// Do not execute a queued management mutation after its caller's budget.
    BeforeDeadline {
        deadline: Instant,
        command: Box<TpmCommand>,
    },
    PcrPolicyUpdate(PcrPolicyUpdateCommand),
    SetMigrationPassphrase {
        old_passphrase: Option<Zeroizing<String>>,
        new_passphrase: Zeroizing<String>,
    },
    VerifyMigrationPassphrase {
        passphrase: Zeroizing<String>,
    },
    PcrDigestCheck(PcrDigestCheckCommand),
}

/// Data needed to update a credential's PCR policy via `policy_authorize`.
pub struct PcrPolicyUpdateCommand {
    pub credential_id: Vec<u8>,
    pub pcr_indices: Option<Vec<u32>>,
    pub passphrase: Zeroizing<String>,
}

/// Data needed to check the current PCR digest for a given selection.
pub struct PcrDigestCheckCommand {
    pub pcr_indices: Vec<u32>,
    pub resp_tx: mpsc::Sender<color_eyre::Result<Vec<u8>>>,
}

/// Result type for a TPM command sent across threads.
pub type TpmCmdResult = std::result::Result<(), ManagementError>;

/// Channel sender for dispatching TPM commands from the management thread
/// to the main daemon thread.  Each command carries a one-shot reply channel.
pub type TpmCmdSender = mpsc::Sender<(TpmCommand, mpsc::Sender<TpmCmdResult>)>;

fn get_info_response(client_pin: bool) -> Vec<u8> {
    encode_response(
        cbor!({
            1 => ["FIDO_2_1", "FIDO_2_0"],
            3 => byte_string(AAGUID.to_vec()),
            4 => {
                "plat" => false,
                "rk" => true,
                "up" => true,
                // Host approval collects UP, not built-in UV. PIN verification
                // is available only after the user configures a client PIN.
                "clientPin" => client_pin,
                "pinUvAuthToken" => client_pin,
                "credMgmt" => true,
                "makeCredUvNotRqd" => true,
            },
            6 => [2, 1],
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

fn validate_token_permissions(
    raw_permissions: u64,
    rp_id: Option<&str>,
    allow_missing_rp_id: bool,
) -> Result<Ctap2PermissionFlags, ErrorStatus> {
    if raw_permissions == 0 {
        return Err(ErrorStatus::InvalidParameter);
    }
    // Future permission bits are ignored, not rejected or granted.
    let permissions = Ctap2PermissionFlags::from_bits_truncate(raw_permissions as u8);
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
    match protocol {
        Some(1 | 2) => Ok(()),
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

fn derive_pin_uv_keys(protocol: u64, shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32]), ()> {
    match protocol {
        1 => {
            let key: [u8; 32] = Sha256::digest(shared_secret).into();
            Ok((key, key))
        }
        2 => derive_protocol2_keys(shared_secret),
        _ => Err(()),
    }
}

fn verify_pin_uv_auth_param_protocol(
    protocol: u64,
    hmac_key: &[u8; 32],
    auth_param: &[u8],
    message: &[u8],
) -> Result<(), ErrorStatus> {
    let auth_length = if protocol == 1 { 16 } else { 32 };
    if auth_param.len() != auth_length {
        return Err(ErrorStatus::PinAuthInvalid);
    }
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| ErrorStatus::OperationDenied)?;
    mac.update(message);
    let expected = mac.finalize().into_bytes();
    constant_time_equal(&expected[..auth_length], auth_param)
        .then_some(())
        .ok_or(ErrorStatus::PinAuthInvalid)
}

fn encrypt_aes_protocol(
    protocol: u64,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, ErrorStatus> {
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
        return Err(ErrorStatus::InvalidParameter);
    }
    let mut iv = [0u8; 16];
    if protocol == 2 {
        fill_random(&mut iv);
    }
    let mut encrypted = plaintext.to_vec();
    let length = encrypted.len();
    Aes256CbcEncryptor::new(key.into(), (&iv).into())
        .encrypt_padded::<NoPadding>(&mut encrypted, length)
        .map_err(|_| ErrorStatus::OperationDenied)?;
    if protocol == 1 {
        Ok(encrypted)
    } else {
        let mut result = iv.to_vec();
        result.extend(encrypted);
        Ok(result)
    }
}

fn decrypt_aes_protocol(
    protocol: u64,
    key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ErrorStatus> {
    if ciphertext.is_empty()
        || !ciphertext.len().is_multiple_of(16)
        || (protocol == 2 && ciphertext.len() < 32)
    {
        return Err(ErrorStatus::InvalidParameter);
    }
    let (iv, data): (&[u8; 16], &[u8]) = if protocol == 1 {
        (&[0u8; 16], ciphertext)
    } else {
        (
            ciphertext[..16]
                .try_into()
                .map_err(|_| ErrorStatus::InvalidParameter)?,
            &ciphertext[16..],
        )
    };
    let mut decrypted = data.to_vec();
    let plaintext = Aes256CbcDecryptor::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut decrypted)
        .map_err(|_| ErrorStatus::OperationDenied)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
fn encrypt_aes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    encrypt_aes_protocol(2, key, plaintext)
}

#[cfg(test)]
fn decrypt_aes(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    decrypt_aes_protocol(2, key, ciphertext)
}

#[cfg(test)]
fn verify_pin_uv_auth_param(
    key: &[u8; 32],
    auth_param: &[u8],
    message: &[u8],
) -> Result<(), ErrorStatus> {
    verify_pin_uv_auth_param_protocol(2, key, auth_param, message)
}

fn decrypt_pin(protocol: u64, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, ErrorStatus> {
    let decrypted = decrypt_aes_protocol(protocol, key, encrypted)?;
    let Some(first_zero) = decrypted.iter().position(|byte| *byte == 0) else {
        return Ok(decrypted);
    };
    if decrypted[first_zero..].iter().any(|byte| *byte != 0) {
        return Err(ErrorStatus::PinPolicyViolation);
    }
    Ok(decrypted[..first_zero].to_vec())
}

fn decrypt_pin_hash(
    protocol: u64,
    key: &[u8; 32],
    encrypted: &[u8],
) -> Result<Vec<u8>, ErrorStatus> {
    let decrypted = decrypt_aes_protocol(protocol, key, encrypted)?;
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
    authority: Option<&store::StoredMigrationAuthority>,
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
    let pcr_indices = credential_pcr_indices(policy).wrap_err("parsing stored PCR selection")?;
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
    let authority_key = authority.map(store::StoredMigrationAuthority::authority);
    tpm.sign_digest_with_policy(
        key,
        policy_binding.as_ref(),
        authority_key.as_ref(),
        &digest,
    )
}

fn credential_pcr_indices(
    policy: Option<&store::StoredPcrPolicy>,
) -> color_eyre::Result<Option<Vec<u32>>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    if policy.selection == "none" {
        return Ok(None);
    }
    tpm::pcr_indices_from_selection(&policy.selection).map(Some)
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
mod credentials_audit_tests;
#[cfg(test)]
mod pin_compliance_tests;
#[cfg(test)]
mod protocol1_compliance_tests;
#[cfg(test)]
mod tests;
