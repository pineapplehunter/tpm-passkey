use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
};

use color_eyre::{
    Result,
    eyre::{WrapErr, eyre},
};
use sha2::{Digest as ShaDigest, Sha256};
use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    constants::{
        CommandCode, SessionType,
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    },
    handles::{ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Auth, Digest, DigestList, EccPoint, EccScheme, HashScheme, Name, Nonce, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, RsaExponent, Signature, SignatureScheme,
        SymmetricDefinitionObject, Ticket,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
    utils::{self, PublicKey},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrPolicyBinding {
    pub selection: String,
    pub digest: Vec<u8>,
    pub policy_ref: Option<Vec<u8>>,
    pub authority_name: Option<Vec<u8>>,
    pub authority_signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TpmCredential {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
    pub auth_value: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for TpmCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TpmCredential")
            .field("has_authorization", &self.auth_value.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct TpmConfig {
    pub device: PathBuf,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            device: PathBuf::from("/dev/tpmrm0"),
        }
    }
}

pub fn check_device(path: &Path) -> std::io::Result<()> {
    std::fs::metadata(path).map(|_| ())
}

pub fn public_name(public_blob: &[u8]) -> Result<Vec<u8>> {
    let public = Public::unmarshall(public_blob).wrap_err("unmarshalling TPM public area")?;
    let encoded = public.marshall().wrap_err("marshalling TPM public area")?;
    let digest = Sha256::digest(encoded);
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&0x000b_u16.to_be_bytes());
    name.extend_from_slice(&digest);
    Ok(name)
}

pub fn credential_policy_ref(credential_id: &[u8]) -> Vec<u8> {
    let mut value = b"tpm-passkey/pcr-policy/v2".to_vec();
    value.extend_from_slice(credential_id);
    Sha256::digest(value).to_vec()
}

struct PolicySessionGuard {
    context: *mut Context,
    session: PolicySession,
}

struct ObjectHandleGuard {
    context: *mut Context,
    handle: ObjectHandle,
}

impl Drop for ObjectHandleGuard {
    fn drop(&mut self) {
        // Safety: the guard is created from &mut Tpm and dropped before the
        // &mut borrow is released, so no aliasing &mut references exist.
        let ctx = unsafe { &mut *self.context };
        let _ = ctx.flush_context(self.handle);
    }
}

impl Drop for PolicySessionGuard {
    fn drop(&mut self) {
        let handle: SessionHandle = self.session.into();
        // Safety: the guard is created from &mut Tpm and dropped before the
        // &mut borrow is released, so no aliasing &mut references exist.
        let ctx = unsafe { &mut *self.context };
        let _ = ctx.flush_context(handle.into());
    }
}

pub struct Tpm {
    context: Context,
    pcr_selection_list: PcrSelectionList,
    pcr_selection_name: String,
}

impl Tpm {
    pub fn open(path: &Path, pcr_indices: Option<&[u32]>) -> Result<Self> {
        let tcti = format!("device:{}", path.display())
            .parse::<TctiNameConf>()
            .wrap_err_with(|| format!("creating TPM TCTI config for {}", path.display()))?;
        let context = Context::new(tcti)
            .wrap_err_with(|| format!("opening TPM ESAPI context for {}", path.display()))?;
        let (pcr_selection_list, pcr_selection_name) = default_pcr_selection(pcr_indices)?;
        Ok(Self {
            context,
            pcr_selection_list,
            pcr_selection_name,
        })
    }

    /// Select the PCRs used by subsequent policy creation, update, and signing.
    pub fn set_pcr_indices(&mut self, pcr_indices: &[u32]) -> Result<()> {
        let (selection, name) = default_pcr_selection(Some(pcr_indices))?;
        self.pcr_selection_list = selection;
        self.pcr_selection_name = name;
        Ok(())
    }

    pub fn probe(&mut self) -> Result<()> {
        let random = self
            .context
            .get_random(8)
            .wrap_err("reading random bytes from TPM")?;
        log::info!(
            "TPM probe succeeded; RNG returned {} bytes",
            random.value().len()
        );
        self.probe_ecc_signing()
            .wrap_err("probing TPM ECC signing")?;
        Ok(())
    }

    pub fn create_credential_key(&mut self) -> Result<TpmCredential> {
        self.create_credential_key_with_auth(None)
    }

    /// A distinct TPM migration authority with a random authorization value.
    /// The caller must encrypt that value before persisting any migration data.
    pub fn create_migration_authority(&mut self) -> Result<TpmCredential> {
        let mut auth = Zeroizing::new(vec![0; 32]);
        getrandom::fill(&mut auth).wrap_err("generating TPM migration authorization")?;
        self.create_credential_key_with_auth(Some(&auth))
    }

    pub fn create_credential_key_with_policy(
        &mut self,
        policy: Option<&PcrPolicyBinding>,
    ) -> Result<TpmCredential> {
        self.create_credential_key_with_policy_and_auth(policy, None)
    }

    fn create_credential_key_with_auth(
        &mut self,
        auth_value: Option<&[u8]>,
    ) -> Result<TpmCredential> {
        self.create_credential_key_with_policy_and_auth(None, auth_value)
    }

    fn create_credential_key_with_policy_and_auth(
        &mut self,
        policy: Option<&PcrPolicyBinding>,
        auth_value: Option<&[u8]>,
    ) -> Result<TpmCredential> {
        let parent = self.create_storage_parent()?;
        let public = signing_key_public(policy)?;
        let auth = auth_value
            .map(|value| Auth::try_from(value.to_vec()))
            .transpose()
            .wrap_err("building TPM authority auth value")?;

        let key = self.context.execute_with_nullauth_session(|context| {
            context.create(parent, public, auth, None, None, None)
        });
        self.context
            .flush_context(parent.into())
            .wrap_err("flushing transient TPM storage parent")?;
        let key = key.wrap_err("creating TPM credential signing key")?;
        let PublicKey::Ecc { x, y } = PublicKey::try_from(key.out_public.clone())
            .wrap_err("extracting TPM credential public key")?
        else {
            color_eyre::eyre::bail!("TPM credential key is not ECC");
        };

        Ok(TpmCredential {
            private: key.out_private.value().to_vec(),
            public: key
                .out_public
                .marshall()
                .wrap_err("marshalling TPM credential public blob")?,
            public_key_x: x,
            public_key_y: y,
            auth_value: auth_value.map(|value| Zeroizing::new(value.to_vec())),
        })
    }

    pub fn create_secure_boot_policy(&mut self) -> Result<PcrPolicyBinding> {
        let selection_list = self.pcr_selection_list.clone();
        let current_digest = self.current_pcr_digest(&selection_list)?;
        let trial_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let trial_session = PolicySession::try_from(trial_session)?;
        self.context.policy_pcr(
            trial_session,
            Digest::try_from(current_digest.clone())?,
            selection_list,
        )?;
        let policy_digest = self.context.policy_get_digest(trial_session)?;
        log::debug!(
            "create_secure_boot_policy: pcr_digest={} policy_digest={}",
            hex::encode(&current_digest),
            hex::encode(policy_digest.value()),
        );
        self.context
            .flush_context(SessionHandle::from(trial_session).into())?;

        Ok(PcrPolicyBinding {
            selection: self.pcr_selection_name.clone(),
            digest: policy_digest.value().to_vec(),
            policy_ref: None,
            authority_name: None,
            authority_signature: None,
        })
    }

    pub fn policy_with_ref_hash(policy_digest: &[u8], policy_ref: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(policy_digest);
        hasher.update(policy_ref);
        hasher.finalize().to_vec()
    }

    pub fn sign_migration_policy(
        &mut self,
        authority: &TpmCredential,
        approved_policy: &[u8],
        policy_ref: &[u8],
    ) -> Result<Vec<u8>> {
        if approved_policy.len() != 32 {
            color_eyre::eyre::bail!("approved PCR policy must be a SHA-256 digest");
        }
        let to_sign = Self::policy_with_ref_hash(approved_policy, policy_ref);
        let parent = self.create_storage_parent()?;
        let private = Private::try_from(authority.private.clone())?;
        let public = Public::unmarshall(&authority.public)?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))?;
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.as_slice())?)?;
        }
        let digest = Digest::try_from(to_sign)?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = self
            .context
            .execute_with_session(Some(AuthSession::Password), |context| {
                context.sign(
                    key_handle,
                    digest,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
            .wrap_err("signing approved PCR policy")?;
        self.context.flush_context(key_handle.into())?;
        self.context.flush_context(parent.into())?;
        signature
            .marshall()
            .wrap_err("marshalling approved PCR policy signature")
    }

    /// Create a PolicyAuthorize-protected baseline with no PCR constraints.
    /// The approved policy is the initial (all-zero) policy-session digest; the
    /// resulting key policy still restricts use to TPM2_Sign.
    pub fn create_authorized_baseline_policy(
        &mut self,
        authority: &TpmCredential,
        policy_ref: &[u8],
    ) -> Result<PcrPolicyBinding> {
        let approved_policy = vec![0u8; 32];
        let signature_bytes =
            self.sign_migration_policy(authority, &approved_policy, policy_ref)?;
        let signature = Signature::unmarshall(&signature_bytes)?;
        let parent = self.create_storage_parent()?;
        let key_handle = self.context.execute_with_nullauth_session(|context| {
            context.load(
                parent,
                Private::try_from(authority.private.clone())?,
                Public::unmarshall(&authority.public)?,
            )
        })?;
        let (_, authority_name, _) = self.context.read_public(key_handle)?;
        let authority_name_bytes = authority_name.value().to_vec();
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.as_slice())?)?;
        }
        let to_sign = Self::policy_with_ref_hash(&approved_policy, policy_ref);
        let ticket = self.context.execute_without_session(|context| {
            context.verify_signature(key_handle, Digest::try_from(to_sign)?, signature)
        })?;
        self.context.flush_context(key_handle.into())?;
        self.context.flush_context(parent.into())?;

        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| eyre!("TPM returned no trial policy session"))?;
        let session = PolicySession::try_from(session)?;
        self.context.policy_authorize(
            session,
            Digest::try_from(approved_policy)?,
            Nonce::try_from(policy_ref.to_vec())?,
            &Name::try_from(authority_name_bytes.clone())?,
            ticket,
        )?;
        self.context
            .policy_command_code(session, CommandCode::Sign)?;
        let final_digest = self.context.policy_get_digest(session)?;
        self.context
            .flush_context(SessionHandle::from(session).into())?;

        Ok(PcrPolicyBinding {
            selection: "none".to_owned(),
            digest: final_digest.value().to_vec(),
            policy_ref: Some(policy_ref.to_vec()),
            authority_name: Some(authority_name_bytes),
            authority_signature: Some(signature_bytes),
        })
    }

    pub fn create_authorized_policy(
        &mut self,
        approved: &PcrPolicyBinding,
        authority: &TpmCredential,
        policy_ref: &[u8],
    ) -> Result<PcrPolicyBinding> {
        let policy_digest = &approved.digest;
        let to_sign = Self::policy_with_ref_hash(policy_digest, policy_ref);
        let signature_bytes = self.sign_migration_policy(authority, policy_digest, policy_ref)?;
        let signature = Signature::unmarshall(&signature_bytes)?;
        let parent = self.create_storage_parent()?;
        let key_handle = self.context.execute_with_nullauth_session(|context| {
            context.load(
                parent,
                Private::try_from(authority.private.clone())?,
                Public::unmarshall(&authority.public)?,
            )
        })?;
        let (_, authority_name, _) = self.context.read_public(key_handle)?;
        let authority_name_bytes = authority_name.value().to_vec();
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.as_slice())?)?;
        }
        log::debug!(
            "create_authorized_policy: policy_digest={} hex={}, to_sign={} hex={}, policy_ref={} bytes, key_name={} bytes",
            policy_digest.len(),
            hex::encode(policy_digest),
            to_sign.len(),
            hex::encode(&to_sign),
            policy_ref.len(),
            authority_name_bytes.len(),
        );
        let ticket = self.context.execute_without_session(|context| {
            context.verify_signature(key_handle, Digest::try_from(to_sign)?, signature)
        })?;
        log::debug!(
            "verify_signature produced ticket: tag={:?}, hierarchy={:?}, ticket_digest={} hex={}",
            ticket.tag(),
            ticket.hierarchy(),
            ticket.digest().len(),
            hex::encode(ticket.digest()),
        );
        self.context.flush_context(parent.into())?;

        let selection = self.pcr_selection_list.clone();
        let current_digest = self.current_pcr_digest(&selection)?;
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let session = PolicySession::try_from(session)?;
        self.context
            .policy_pcr(session, Digest::try_from(current_digest)?, selection)?;
        self.context.policy_authorize(
            session,
            Digest::try_from(policy_digest.clone())?,
            Nonce::try_from(policy_ref.to_vec())?,
            &Name::try_from(authority_name_bytes.clone())?,
            ticket,
        )?;
        self.context.flush_context(key_handle.into())?;
        self.context
            .policy_command_code(session, CommandCode::Sign)?;
        let final_digest = self.context.policy_get_digest(session)?;
        self.context
            .flush_context(SessionHandle::from(session).into())?;

        Ok(PcrPolicyBinding {
            selection: approved.selection.clone(),
            digest: final_digest.value().to_vec(),
            policy_ref: Some(policy_ref.to_vec()),
            authority_name: Some(authority_name_bytes),
            authority_signature: Some(signature_bytes),
        })
    }

    pub fn update_authorized_policy(
        &mut self,
        authority: &TpmCredential,
        authority_name: &[u8],
        policy_ref: &[u8],
    ) -> Result<PcrPolicyBinding> {
        let selection = self.pcr_selection_list.clone();
        let current_digest = self.current_pcr_digest(&selection)?;
        let trial_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let trial_session = PolicySession::try_from(trial_session)?;
        self.context.policy_pcr(
            trial_session,
            Digest::try_from(current_digest.clone())?,
            selection.clone(),
        )?;
        let pcr_policy_digest = self.context.policy_get_digest(trial_session)?;
        self.context
            .flush_context(SessionHandle::from(trial_session).into())?;

        let to_sign = Self::policy_with_ref_hash(pcr_policy_digest.value(), policy_ref);
        let parent = self.create_storage_parent()?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| {
                context.load(
                    parent,
                    Private::try_from(authority.private.clone())?,
                    Public::unmarshall(&authority.public)?,
                )
            })
            .wrap_err("loading authority key for PCR update")?;
        if let Some(auth_value) = &authority.auth_value {
            self.context
                .tr_set_auth(key_handle.into(), Auth::try_from(auth_value.as_slice())?)?;
        }
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = self
            .context
            .execute_with_session(Some(AuthSession::Password), |context| {
                context.sign(
                    key_handle,
                    Digest::try_from(to_sign.clone())?,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
            .wrap_err("signing updated PCR policy with authority key")?;
        let ticket = self
            .context
            .execute_without_session(|context| {
                context.verify_signature(key_handle, Digest::try_from(to_sign)?, signature.clone())
            })
            .wrap_err("verifying updated PCR policy signature")?;
        self.context.flush_context(key_handle.into())?;

        let new_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no trial policy session"))?;
        let new_session = PolicySession::try_from(new_session)?;
        self.context
            .policy_pcr(new_session, Digest::try_from(current_digest)?, selection)?;
        self.context.policy_authorize(
            new_session,
            pcr_policy_digest,
            Nonce::try_from(policy_ref.to_vec())?,
            &Name::try_from(authority_name.to_vec())?,
            ticket,
        )?;
        self.context
            .policy_command_code(new_session, CommandCode::Sign)?;
        let final_digest = self.context.policy_get_digest(new_session)?;
        self.context
            .flush_context(SessionHandle::from(new_session).into())?;
        self.context.flush_context(parent.into())?;

        let signature_bytes = signature
            .marshall()
            .wrap_err("marshalling updated PCR policy signature")?;

        Ok(PcrPolicyBinding {
            selection: self.pcr_selection_name.clone(),
            digest: final_digest.value().to_vec(),
            policy_ref: Some(policy_ref.to_vec()),
            authority_name: Some(authority_name.to_vec()),
            authority_signature: Some(signature_bytes),
        })
    }

    pub fn sign_digest(&mut self, credential: &TpmCredential, digest: &[u8]) -> Result<Vec<u8>> {
        self.sign_digest_with_policy(credential, None, None, digest)
    }

    pub fn sign_digest_with_policy(
        &mut self,
        credential: &TpmCredential,
        policy: Option<&PcrPolicyBinding>,
        authority: Option<&TpmCredential>,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            color_eyre::eyre::bail!("TPM ECDSA signing digest must be 32 bytes");
        }

        let parent = self.create_storage_parent()?;
        let _parent_guard = ObjectHandleGuard {
            context: &mut self.context as *mut Context,
            handle: parent.into(),
        };
        let private = Private::try_from(credential.private.clone())
            .wrap_err("building TPM credential private blob")?;
        let public = Public::unmarshall(&credential.public)
            .wrap_err("unmarshalling TPM credential public blob")?;
        log::debug!(
            "sign_digest_with_policy: policy={:?} authority={:?} stored_digest={}",
            policy.is_some(),
            authority.is_some(),
            policy.map(|p| hex::encode(&p.digest)).unwrap_or_default(),
        );
        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| context.load(parent, private, public))
            .wrap_err("loading TPM credential signing key")?;
        let _key_guard = ObjectHandleGuard {
            context: &mut self.context as *mut Context,
            handle: key_handle.into(),
        };

        let digest = Digest::try_from(digest.to_vec()).wrap_err("building TPM signing digest")?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let signature = if let (
            Some(_policy),
            Some(authority),
            Some(policy_ref),
            Some(authority_name),
            Some(authority_signature),
        ) = (
            policy,
            authority,
            policy.and_then(|policy| policy.policy_ref.as_ref()),
            policy.and_then(|policy| policy.authority_name.as_ref()),
            policy.and_then(|policy| policy.authority_signature.as_ref()),
        ) {
            let no_pcr = policy.is_some_and(|binding| binding.selection == "none");
            let selection_list = self.pcr_selection_list.clone();
            let current_digest = if no_pcr {
                None
            } else {
                Some(self.current_pcr_digest(&selection_list)?)
            };
            let policy_session = self
                .context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no policy session"))?;
            let policy_session = PolicySession::try_from(policy_session)?;
            let _policy_session_guard = PolicySessionGuard {
                context: &mut self.context as *mut Context,
                session: policy_session,
            };
            if let Some(current_digest) = current_digest {
                self.context.policy_pcr(
                    policy_session,
                    Digest::try_from(current_digest)?,
                    selection_list,
                )?;
            }
            let approved_policy = self.context.policy_get_digest(policy_session)?;
            let authority_handle = self.context.execute_with_nullauth_session(|context| {
                context.load(
                    parent,
                    Private::try_from(authority.private.clone())?,
                    Public::unmarshall(&authority.public)?,
                )
            })?;
            let _authority_guard = ObjectHandleGuard {
                context: &mut self.context as *mut Context,
                handle: authority_handle.into(),
            };
            let (_, actual_name, _) = self.context.read_public(authority_handle)?;
            if actual_name.value() != authority_name.as_slice() {
                color_eyre::eyre::bail!("migration authority name does not match the credential");
            }
            log::debug!(
                "policy_authorize: approved_policy={} hex={}, policy_ref={} bytes, key_name={} bytes, key_name_hex={}",
                approved_policy.len(),
                hex::encode(approved_policy.value()),
                policy_ref.len(),
                actual_name.value().len(),
                hex::encode(actual_name.value()),
            );
            // Per TPM spec, PolicyAuthorize computes
            //   aHash = hash(nameAlg of keySign, approvedPolicy || policyRef)
            // and validates the ticket against aHash, not against approvedPolicy
            // directly.  We must therefore verify the stored signature over
            // SHA-256(approvedPolicy || policyRef), not over approvedPolicy alone.
            let to_sign = Self::policy_with_ref_hash(approved_policy.value(), policy_ref);
            let ticket = self
                .context
                .execute_without_session(|context| {
                    context.verify_signature(
                        authority_handle,
                        Digest::try_from(to_sign)?,
                        Signature::unmarshall(authority_signature)?,
                    )
                })
                .wrap_err("verifying PolicyAuthorize authority signature")?;
            log::debug!(
                "verify_signature ticket: tag={:?} hierarchy={:?} digest={} hex={}",
                ticket.tag(),
                ticket.hierarchy(),
                ticket.digest().len(),
                hex::encode(ticket.digest()),
            );
            self.context.policy_authorize(
                policy_session,
                approved_policy,
                Nonce::try_from(policy_ref.clone())?,
                &actual_name,
                ticket,
            )?;
            self.context
                .policy_command_code(policy_session, CommandCode::Sign)?;

            self.context
                .execute_with_session(Some(AuthSession::from(policy_session)), |context| {
                    context.sign(
                        key_handle,
                        digest.clone(),
                        SignatureScheme::Null,
                        validation.try_into()?,
                    )
                })
        } else if policy.is_some_and(|binding| binding.selection == "none") {
            color_eyre::eyre::bail!(
                "PCR-disabled policy binding is missing PolicyAuthorize authority metadata"
            );
        } else if policy.is_some() {
            let selection_list = self.pcr_selection_list.clone();
            let current_digest = self.current_pcr_digest(&selection_list)?;
            log::debug!(
                "assertion policy path: pcr_digest={}",
                hex::encode(&current_digest),
            );
            let policy_session = self
                .context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .ok_or_else(|| color_eyre::eyre::eyre!("TPM returned no policy session"))?;
            let policy_session = PolicySession::try_from(policy_session)?;
            let _policy_session_guard = PolicySessionGuard {
                context: &mut self.context as *mut Context,
                session: policy_session,
            };
            self.context.policy_pcr(
                policy_session,
                Digest::try_from(current_digest)?,
                selection_list,
            )?;
            let sign_result = self.context.execute_with_session(
                Some(AuthSession::from(policy_session)),
                |context| {
                    context.sign(
                        key_handle,
                        digest.clone(),
                        SignatureScheme::Null,
                        validation.try_into()?,
                    )
                },
            );
            log::debug!("assertion policy path: sign result={sign_result:?}");
            sign_result
        } else {
            self.context.execute_with_nullauth_session(|context| {
                context.sign(
                    key_handle,
                    digest,
                    SignatureScheme::Null,
                    validation.try_into()?,
                )
            })
        };

        let signature = signature.wrap_err("signing digest with TPM credential key")?;
        let Signature::EcDsa(signature) = signature else {
            color_eyre::eyre::bail!("TPM returned non-ECDSA signature");
        };

        Ok(ecdsa_der(
            signature.signature_r().value(),
            signature.signature_s().value(),
        ))
    }

    pub fn current_pcr_digest(&mut self, selection_list: &PcrSelectionList) -> Result<Vec<u8>> {
        let (_, _, digest_list): (u32, PcrSelectionList, DigestList) =
            self.context.pcr_read(selection_list.clone())?;
        let mut hasher = Sha256::new();
        for digest in digest_list.value() {
            hasher.update(digest.value());
        }
        let combined = hasher.finalize().to_vec();
        log::debug!(
            "current_pcr_digest: selection={:?} n_digests={} combined={}",
            selection_list,
            digest_list.value().len(),
            hex::encode(&combined),
        );
        for (i, d) in digest_list.value().iter().enumerate() {
            log::debug!("  digest[{}] = {}", i, hex::encode(d.value()));
        }
        Ok(combined)
    }

    fn probe_ecc_signing(&mut self) -> Result<()> {
        let public = signing_key_public(None)?;

        let key_handle = self
            .context
            .execute_with_nullauth_session(|context| {
                context.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .wrap_err("creating transient TPM ECC signing key")?
            .key_handle;
        let digest = Digest::try_from(vec![0u8; 32]).wrap_err("building TPM signing digest")?;
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let signature = self.context.execute_with_nullauth_session(|context| {
            context.sign(
                key_handle,
                digest,
                SignatureScheme::Null,
                validation.try_into()?,
            )
        });
        self.context
            .flush_context(key_handle.into())
            .wrap_err("flushing transient TPM ECC signing key")?;
        let signature = signature.wrap_err("signing digest with transient TPM ECC key")?;
        let Signature::EcDsa(signature) = signature else {
            color_eyre::eyre::bail!("TPM returned non-ECDSA signature");
        };

        log::info!(
            "TPM ECC signing probe succeeded; r={} bytes s={} bytes",
            signature.signature_r().value().len(),
            signature.signature_s().value().len()
        );
        Ok(())
    }

    fn create_storage_parent(&mut self) -> Result<tss_esapi::handles::KeyHandle> {
        let public = utils::create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .wrap_err("building TPM storage-parent template")?;
        Ok(self
            .context
            .execute_with_nullauth_session(|context| {
                context.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .wrap_err("creating transient TPM storage parent")?
            .key_handle)
    }
}

fn signing_key_public(policy: Option<&PcrPolicyBinding>) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        // Without a policy, allow the ordinary auth-value path (empty for
        // unbound passkeys, random for migration authorities). Policy-bound
        // passkeys must NOT have an auth-value bypass.
        .with_user_with_auth(policy.is_none())
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .wrap_err("building TPM object attributes")?;

    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default());

    if let Some(policy) = policy {
        builder = builder.with_auth_policy(Digest::try_from(policy.digest.clone())?);
    }

    builder
        .build()
        .wrap_err("building TPM ECC signing-key template")
}

pub fn pcr_selection_for_indices(pcr_indices: &[u32]) -> Result<PcrSelectionList> {
    if pcr_indices.is_empty() {
        return Err(eyre!("at least one PCR index is required"));
    }
    if let Some(index) = pcr_indices.iter().find(|&&index| index > 23) {
        return Err(eyre!("invalid PCR index {index}; expected 0..=23"));
    }
    let mut unique = pcr_indices.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != pcr_indices.len() {
        return Err(eyre!("duplicate PCR indices are not allowed"));
    }

    let slots: Result<Vec<PcrSlot>> = pcr_indices
        .iter()
        .map(|&index| {
            PcrSlot::try_from(1u32 << index).map_err(|_| eyre!("invalid PCR index {index}"))
        })
        .collect();
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots?)
        .build()
        .wrap_err("building PCR selection list")
}

pub fn pcr_indices_from_selection(selection: &str) -> Result<Vec<u32>> {
    let (algorithm, indices) = selection
        .split_once(':')
        .ok_or_else(|| eyre!("invalid PCR selection {selection:?}"))?;
    if algorithm != "sha256" {
        return Err(eyre!("unsupported PCR bank {algorithm:?}"));
    }
    let indices = indices
        .split(',')
        .map(|index| {
            index
                .trim()
                .parse::<u32>()
                .wrap_err_with(|| format!("invalid PCR index {index:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    pcr_selection_for_indices(&indices)?;
    Ok(indices)
}

fn default_pcr_selection(pcr_indices: Option<&[u32]>) -> Result<(PcrSelectionList, String)> {
    let indices = pcr_indices.unwrap_or(&[7]);
    let name = format!(
        "sha256:{}",
        indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let selection = pcr_selection_for_indices(indices)?;
    Ok((selection, name))
}

fn ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r = der_integer(r);
    let s = der_integer(s);
    let mut der = Vec::with_capacity(2 + r.len() + s.len());
    der.push(0x30);
    der.push((r.len() + s.len()) as u8);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    der
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let mut integer = if first_nonzero == value.len() {
        vec![0]
    } else {
        value[first_nonzero..].to_vec()
    };
    if integer[0] & 0x80 != 0 {
        integer.insert(0, 0);
    }

    let mut der = Vec::with_capacity(2 + integer.len());
    der.push(0x02);
    der.push(integer.len() as u8);
    der.extend_from_slice(&integer);
    der
}

#[cfg(test)]
mod tests {
    use super::{
        PcrPolicyBinding, pcr_indices_from_selection, pcr_selection_for_indices, signing_key_public,
    };

    #[test]
    fn unbound_keys_have_no_policy_but_both_modes_remain_nonexportable() {
        let policy = PcrPolicyBinding {
            selection: "sha256:7".into(),
            digest: vec![0x42; 32],
            policy_ref: None,
            authority_name: None,
            authority_signature: None,
        };
        for binding in [None, Some(&policy)] {
            let public = signing_key_public(binding).unwrap();
            let attributes = public.object_attributes();
            assert!(attributes.fixed_tpm());
            assert!(attributes.fixed_parent());
            assert!(attributes.sensitive_data_origin());
            assert!(attributes.sign_encrypt());
            assert_eq!(attributes.user_with_auth(), binding.is_none());
            assert_eq!(public.auth_policy().value().is_empty(), binding.is_none());
        }
    }

    #[test]
    fn pcr_disabled_authorized_binding_has_policy_and_no_auth_bypass() {
        let binding = PcrPolicyBinding {
            selection: "none".into(),
            digest: vec![0x42; 32],
            policy_ref: Some(vec![1]),
            authority_name: Some(vec![2]),
            authority_signature: Some(vec![3]),
        };
        let public = signing_key_public(Some(&binding)).unwrap();
        assert!(!public.object_attributes().user_with_auth());
        assert_eq!(public.auth_policy().value(), binding.digest.as_slice());
    }

    #[test]
    fn pcr_selection_validation_rejects_invalid_input() {
        assert!(pcr_selection_for_indices(&[]).is_err());
        assert!(pcr_selection_for_indices(&[7, 7]).is_err());
        assert!(pcr_selection_for_indices(&[24]).is_err());
        assert!(pcr_selection_for_indices(&[1, 7]).is_ok());
    }

    #[test]
    fn stored_pcr_selection_round_trips() {
        assert_eq!(
            pcr_indices_from_selection("sha256:1,7").expect("valid selection"),
            vec![1, 7]
        );
        assert!(pcr_indices_from_selection("sha1:7").is_err());
        assert!(pcr_indices_from_selection("sha256:").is_err());
    }
}
