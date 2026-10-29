//! Cryptographic primitives for passphrase-protected migration keys.
//!
//! Create the configuration during explicit migration-key setup, not while
//! enrolling credentials. Enrollment uses only [`MigrationConfig::public_key`]
//! and [`encrypt`]; the private scalar is never needed or stored there.
//!
//! A valid config is not proof that its public key was approved: an attacker
//! able to replace both the database and its key can substitute a self-made
//! config. Trust must be established at enrollment (for example, by the
//! explicit user-approved setup flow); this format does not claim a MAC can
//! protect against root or simultaneous database-and-key compromise.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version as ArgonVersion};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION: u32 = 1;
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AUTHORIZATION_LEN: usize = 32;
const MAX_CONTEXT_LEN: usize = 4096;
const CONFIG_DOMAIN: &[u8] = b"tpm-passkey/migration-config/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"tpm-passkey/migration-envelope/v1\0";
const HKDF_DOMAIN: &[u8] = b"tpm-passkey/migration-ecies/aes-256-gcm/v1\0";

/// Passphrase-protected P-256 migration key configuration, version 1.
/// Public key is canonical compressed SEC1 hex. Ciphertext includes GCM tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationConfig {
    pub version: u32,
    pub public_key: String,
    pub kdf_salt: [u8; 32],
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub nonce: [u8; NONCE_LEN],
    pub encrypted_scalar: Vec<u8>,
}

/// Per-credential public-key envelope. The caller supplies identical context
/// bytes at encryption and decryption (credential ID, authority, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationEnvelope {
    pub version: u32,
    /// Canonical compressed SEC1 ephemeral P-256 public key.
    pub ephemeral_public_key: Vec<u8>,
    pub salt: [u8; 32],
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte AES-GCM tag.
    pub ciphertext: Vec<u8>,
}

/// Create a random P-256 key and encrypt its scalar under the passphrase.
/// Call only for explicit configuration/setup, never as part of enrollment.
pub fn create_configuration(passphrase: &str) -> Result<MigrationConfig, CryptoError> {
    validate_passphrase(passphrase)?;
    let secret = random_secret()?;
    config_from_secret(&secret, passphrase)
}

/// Re-encrypt the same private key with a new passphrase and fresh KDF salt
/// and nonce. The public key remains unchanged.
pub fn change_passphrase(
    config: &MigrationConfig,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<MigrationConfig, CryptoError> {
    validate_passphrase(new_passphrase)?;
    let scalar = unlock_scalar(config, old_passphrase)?;
    config_from_scalar(&scalar, &config.public_key, new_passphrase)
}

/// Encrypt a fixed-size TPM migration authorization to the configured public key.
pub fn encrypt(
    public_key: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<MigrationEnvelope, CryptoError> {
    if context.len() > MAX_CONTEXT_LEN || plaintext.len() != AUTHORIZATION_LEN {
        return Err(CryptoError::Invalid);
    }
    let recipient = parse_public_key(public_key.as_bytes())?;
    let ephemeral = random_secret()?;
    let ephemeral_public = ephemeral.public_key().to_sec1_point(true);
    let ephemeral_bytes = ephemeral_public.as_bytes();
    let recipient_bytes = recipient.to_sec1_point(true);
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let mut salt = [0u8; 32];
    fill_random(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let key = derive_envelope_key(
        shared.raw_secret_bytes().as_slice(),
        &salt,
        ephemeral_bytes,
        recipient_bytes.as_bytes(),
    )?;
    let aad = envelope_aad(context, ephemeral_bytes, recipient_bytes.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Invalid)?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Invalid)?;
    Ok(MigrationEnvelope {
        version: VERSION,
        ephemeral_public_key: ephemeral_bytes.to_vec(),
        salt,
        nonce,
        ciphertext,
    })
}

/// Unlock the scalar and decrypt an envelope, authenticating its supplied
/// context and both public keys. No plaintext is returned on authentication
/// failure.
pub fn decrypt(
    config: &MigrationConfig,
    passphrase: &str,
    envelope: &MigrationEnvelope,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::Invalid);
    }
    validate_envelope(envelope)?;
    let scalar = unlock_scalar(config, passphrase)?;
    let recipient_secret = scalar_secret(&scalar)?;
    let recipient = recipient_secret.public_key();
    let recipient_bytes = recipient.to_sec1_point(true);
    let ephemeral = parse_public_key(&envelope.ephemeral_public_key)?;
    let shared = diffie_hellman(recipient_secret.to_nonzero_scalar(), ephemeral.as_affine());
    let ephemeral_bytes = ephemeral.to_sec1_point(true);
    let key = derive_envelope_key(
        shared.raw_secret_bytes().as_slice(),
        &envelope.salt,
        ephemeral_bytes.as_bytes(),
        recipient_bytes.as_bytes(),
    )?;
    let aad = envelope_aad(
        context,
        ephemeral_bytes.as_bytes(),
        recipient_bytes.as_bytes(),
    );
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Invalid)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if plaintext.len() != AUTHORIZATION_LEN {
        return Err(CryptoError::Invalid);
    }
    Ok(plaintext)
}

/// Canonical bounded associated data for a credential authority envelope.
pub fn authorization_context(
    credential_id: &[u8],
    authority_public: &[u8],
    policy_ref: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if credential_id.is_empty()
        || credential_id.len() > 1024
        || authority_public.is_empty()
        || authority_public.len() > 4096
        || policy_ref.is_empty()
        || policy_ref.len() > 256
    {
        return Err(CryptoError::Invalid);
    }
    let mut context =
        Vec::with_capacity(32 + credential_id.len() + authority_public.len() + policy_ref.len());
    context.extend_from_slice(b"tpm-passkey/migration-authority/v1\0");
    for field in [credential_id, authority_public, policy_ref] {
        context.extend_from_slice(&(field.len() as u32).to_be_bytes());
        context.extend_from_slice(field);
    }
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::Invalid);
    }
    Ok(context)
}

impl MigrationConfig {
    /// Return the canonical compressed public key as lowercase hex.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Invalid,
    UnsupportedVersion,
    Authentication,
    Randomness,
}
impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid migration cryptographic data",
            Self::UnsupportedVersion => "unsupported migration cryptographic version or parameters",
            Self::Authentication => "migration passphrase, context, or ciphertext is invalid",
            Self::Randomness => "secure random generation failed",
        })
    }
}
impl std::error::Error for CryptoError {}

fn validate_passphrase(passphrase: &str) -> Result<(), CryptoError> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        Err(CryptoError::Invalid)
    } else {
        Ok(())
    }
}
fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(output).map_err(|_| CryptoError::Randomness)
}
fn random_secret() -> Result<SecretKey, CryptoError> {
    // Rejection sampling avoids modulo bias and makes entropy acquisition
    // explicit through the project's getrandom dependency.
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fill_random(bytes.as_mut())?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}
fn scalar_secret(scalar: &[u8; 32]) -> Result<SecretKey, CryptoError> {
    SecretKey::from_slice(scalar).map_err(|_| CryptoError::Invalid)
}
fn config_from_secret(
    secret: &SecretKey,
    passphrase: &str,
) -> Result<MigrationConfig, CryptoError> {
    let scalar = Zeroizing::new(secret.to_bytes().into());
    let public = secret.public_key().to_sec1_point(true);
    config_from_scalar(&scalar, &hex::encode(public.as_bytes()), passphrase)
}
fn config_from_scalar(
    scalar: &[u8; 32],
    public_key: &str,
    passphrase: &str,
) -> Result<MigrationConfig, CryptoError> {
    validate_passphrase(passphrase)?;
    let public = parse_public_key(public_key.as_bytes())?;
    let derived = scalar_secret(scalar)?.public_key().to_sec1_point(true);
    if derived.as_bytes() != public.to_sec1_point(true).as_bytes() {
        return Err(CryptoError::Invalid);
    }
    let mut salt = [0u8; 32];
    fill_random(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let mut config = MigrationConfig {
        version: VERSION,
        public_key: hex::encode(public.to_sec1_point(true).as_bytes()),
        kdf_salt: salt,
        kdf_memory_kib: KDF_MEMORY_KIB,
        kdf_iterations: KDF_ITERATIONS,
        kdf_parallelism: KDF_PARALLELISM,
        nonce,
        encrypted_scalar: Vec::new(),
    };
    let key = derive_passphrase_key(&config, passphrase)?;
    let aad = config_aad(&config);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Invalid)?;
    config.encrypted_scalar = cipher
        .encrypt(
            &Nonce::from(config.nonce),
            Payload {
                msg: scalar,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Invalid)?;
    Ok(config)
}
fn unlock_scalar(
    config: &MigrationConfig,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    validate_config(config)?;
    validate_passphrase(passphrase)?;
    let key = derive_passphrase_key(config, passphrase)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Invalid)?;
    let aad = config_aad(config);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(config.nonce),
                Payload {
                    msg: &config.encrypted_scalar,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    let scalar: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Invalid)?;
    let scalar = Zeroizing::new(scalar);
    let derived = scalar_secret(&scalar)?.public_key().to_sec1_point(true);
    let configured = parse_public_key(config.public_key.as_bytes())?.to_sec1_point(true);
    if derived.as_bytes() != configured.as_bytes() {
        return Err(CryptoError::Authentication);
    }
    Ok(scalar)
}
fn validate_config(config: &MigrationConfig) -> Result<(), CryptoError> {
    if config.version != VERSION
        || config.kdf_memory_kib != KDF_MEMORY_KIB
        || config.kdf_iterations != KDF_ITERATIONS
        || config.kdf_parallelism != KDF_PARALLELISM
    {
        return Err(CryptoError::UnsupportedVersion);
    }
    if config.encrypted_scalar.len() != 32 + TAG_LEN {
        return Err(CryptoError::Invalid);
    }
    let canonical = parse_public_key(config.public_key.as_bytes())?.to_sec1_point(true);
    if hex::encode(canonical.as_bytes()) != config.public_key {
        return Err(CryptoError::Invalid);
    }
    Ok(())
}
fn validate_envelope(envelope: &MigrationEnvelope) -> Result<(), CryptoError> {
    if envelope.version != VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    if envelope.ciphertext.len() != AUTHORIZATION_LEN + TAG_LEN {
        return Err(CryptoError::Invalid);
    }
    let key = parse_public_key(&envelope.ephemeral_public_key)?;
    if key.to_sec1_point(true).as_bytes() != envelope.ephemeral_public_key {
        return Err(CryptoError::Invalid);
    }
    Ok(())
}
fn parse_public_key(encoded: &[u8]) -> Result<PublicKey, CryptoError> {
    let bytes = if encoded.len() == 66 && encoded.iter().all(u8::is_ascii_hexdigit) {
        hex::decode(encoded).map_err(|_| CryptoError::Invalid)?
    } else if encoded.len() == 33 {
        encoded.to_vec()
    } else {
        return Err(CryptoError::Invalid);
    };
    if bytes.len() != 33 {
        return Err(CryptoError::Invalid);
    }
    let key = PublicKey::from_sec1_bytes(&bytes).map_err(|_| CryptoError::Invalid)?;
    if key.to_sec1_point(true).as_bytes() != bytes {
        return Err(CryptoError::Invalid);
    }
    Ok(key)
}
fn derive_passphrase_key(
    config: &MigrationConfig,
    passphrase: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Invalid)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &config.kdf_salt, key.as_mut())
        .map_err(|_| CryptoError::Invalid)?;
    Ok(key)
}
fn config_aad(config: &MigrationConfig) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONFIG_DOMAIN.len() + 4 + 33 + 12 + 32 + NONCE_LEN);
    aad.extend_from_slice(CONFIG_DOMAIN);
    aad.extend_from_slice(&config.version.to_be_bytes());
    aad.extend_from_slice(&(config.public_key.len() as u32).to_be_bytes());
    aad.extend_from_slice(config.public_key.as_bytes());
    aad.extend_from_slice(&config.kdf_memory_kib.to_be_bytes());
    aad.extend_from_slice(&config.kdf_iterations.to_be_bytes());
    aad.extend_from_slice(&config.kdf_parallelism.to_be_bytes());
    aad.extend_from_slice(&config.kdf_salt);
    aad.extend_from_slice(&config.nonce);
    aad
}
fn derive_envelope_key(
    shared: &[u8],
    salt: &[u8; 32],
    ephemeral: &[u8],
    recipient: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut info = Vec::with_capacity(HKDF_DOMAIN.len() + 66);
    info.extend_from_slice(HKDF_DOMAIN);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(recipient);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| CryptoError::Invalid)?;
    Ok(key)
}
fn envelope_aad(context: &[u8], ephemeral: &[u8], recipient: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 8 + context.len() + 66);
    aad.extend_from_slice(ENVELOPE_DOMAIN);
    aad.extend_from_slice(&(context.len() as u64).to_be_bytes());
    aad.extend_from_slice(context);
    aad.extend_from_slice(ephemeral);
    aad.extend_from_slice(recipient);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_unlock_and_passphrase_change() {
        let c = create_configuration("old sufficiently long phrase").unwrap();
        assert!(unlock_scalar(&c, "wrong phrase").is_err());
        let changed = change_passphrase(&c, "old sufficiently long phrase", "new phrase").unwrap();
        assert_eq!(c.public_key, changed.public_key);
        assert_ne!(c.kdf_salt, changed.kdf_salt);
        assert!(unlock_scalar(&changed, "old sufficiently long phrase").is_err());
        unlock_scalar(&changed, "new phrase").unwrap();
    }
    #[test]
    fn envelope_roundtrip_context_binding_swaps_and_tampering() {
        let c = create_configuration("some passphrase").unwrap();
        let e = encrypt(
            c.public_key(),
            b"credential one / authority",
            &[0x42; AUTHORIZATION_LEN],
        )
        .unwrap();
        assert_eq!(
            decrypt(&c, "some passphrase", &e, b"credential one / authority")
                .unwrap()
                .as_slice(),
            &[0x42; AUTHORIZATION_LEN]
        );
        assert!(decrypt(&c, "some passphrase", &e, b"credential two / authority").is_err());
        let c2 = create_configuration("some passphrase").unwrap();
        assert!(decrypt(&c2, "some passphrase", &e, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.ciphertext[0] ^= 1;
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.nonce[0] ^= 1;
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.salt[0] ^= 1;
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.ephemeral_public_key[1] ^= 1;
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.ephemeral_public_key.clear();
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e.clone();
        bad.ciphertext.clear();
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
        let mut bad = e;
        bad.version += 1;
        assert!(decrypt(&c, "some passphrase", &bad, b"credential one / authority").is_err());
    }
    #[test]
    fn config_substitution_mismatch_malformed_and_parameter_validation() {
        let c = create_configuration("pass phrase").unwrap();
        let other = create_configuration("pass phrase").unwrap();
        let mut bad = c.clone();
        bad.public_key = other.public_key;
        assert!(unlock_scalar(&bad, "pass phrase").is_err());
        let mut bad = c.clone();
        bad.kdf_iterations += 1;
        assert!(unlock_scalar(&bad, "pass phrase").is_err());
        let mut bad = c.clone();
        bad.version += 1;
        assert!(unlock_scalar(&bad, "pass phrase").is_err());
        let mut bad = c.clone();
        bad.encrypted_scalar.pop();
        assert!(unlock_scalar(&bad, "pass phrase").is_err());
        assert!(encrypt("not a key", b"ctx", b"x").is_err());
        assert!(create_configuration("").is_err());
        let mut bad = c.clone();
        bad.nonce[2] ^= 1;
        assert!(unlock_scalar(&bad, "pass phrase").is_err());
    }
    #[test]
    fn envelope_rejects_nonfixed_authorization_and_oversized_context() {
        let config = create_configuration("bounded inputs passphrase").unwrap();
        assert!(encrypt(config.public_key(), b"ctx", b"short").is_err());
        assert!(encrypt(config.public_key(), &vec![0; MAX_CONTEXT_LEN + 1], &[7; 32]).is_err());
        let mut envelope = encrypt(config.public_key(), b"ctx", &[7; 32]).unwrap();
        envelope.ciphertext.pop();
        assert!(decrypt(&config, "bounded inputs passphrase", &envelope, b"ctx").is_err());
    }

    #[test]
    fn independent_encryption_uses_fresh_ephemeral_key_salt_and_nonce() {
        let c = create_configuration("pass phrase").unwrap();
        let a = encrypt(c.public_key(), b"ctx", &[0x55; 32]).unwrap();
        let b = encrypt(c.public_key(), b"ctx", &[0x55; 32]).unwrap();
        assert_ne!(a.ephemeral_public_key, b.ephemeral_public_key);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
