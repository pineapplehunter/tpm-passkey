//! Password encryption for TPM recovery authorization values, never private scalars.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use color_eyre::{
    Result,
    eyre::{WrapErr, bail, eyre},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VERSION: u32 = 1;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
const CONFIG_AAD: &[u8] = b"linux-tpm-fido2/recovery-config/v1";
const CONFIG_CHECK: &[u8] = b"recovery encryption is unlocked";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    pub version: u32,
    pub salt: [u8; 32],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub protection: Protection,
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext followed by its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Only kept in the authenticator worker's memory; never serialized or logged.
#[derive(Clone)]
pub struct UnlockedRecovery {
    protection: Protection,
    key: Zeroizing<[u8; 32]>,
}

impl UnlockedRecovery {
    pub fn new(passphrase: &str) -> Result<Self> {
        if passphrase.is_empty() {
            bail!("recovery passphrase must not be empty");
        }
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).wrap_err("generating recovery encryption salt")?;
        Self::derive(
            Protection {
                version: VERSION,
                salt,
                memory_kib: MEMORY_KIB,
                iterations: ITERATIONS,
                parallelism: PARALLELISM,
            },
            passphrase,
        )
    }

    fn derive(protection: Protection, passphrase: &str) -> Result<Self> {
        // Bound untrusted KDF settings before allocating memory. Version 1 has
        // one calibrated parameter set; a new format can introduce another.
        if protection.version != VERSION
            || protection.memory_kib != MEMORY_KIB
            || protection.iterations != ITERATIONS
            || protection.parallelism != PARALLELISM
        {
            bail!("unsupported recovery encryption parameters");
        }
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
            .map_err(|e| eyre!("invalid recovery KDF parameters: {e}"))?;
        let mut key = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &protection.salt, key.as_mut())
            .map_err(|e| eyre!("deriving recovery encryption key: {e}"))?;
        Ok(Self { protection, key })
    }

    pub fn unlock(config: &EncryptedSecret, passphrase: &str) -> Result<Self> {
        let unlocked = Self::derive(config.protection.clone(), passphrase)?;
        if unlocked.decrypt(config, CONFIG_AAD)?.as_slice() != CONFIG_CHECK {
            bail!("invalid recovery configuration");
        }
        Ok(unlocked)
    }

    pub fn matches_configuration(&self, config: &EncryptedSecret) -> bool {
        self.decrypt(config, CONFIG_AAD)
            .is_ok_and(|value| value.as_slice() == CONFIG_CHECK)
    }

    pub fn configuration(&self) -> Result<EncryptedSecret> {
        self.encrypt(CONFIG_CHECK, CONFIG_AAD)
    }

    pub fn encrypt(&self, secret: &[u8], aad: &[u8]) -> Result<EncryptedSecret> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).wrap_err("generating recovery encryption nonce")?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| eyre!("invalid recovery encryption key"))?;
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: secret, aad })
            .map_err(|_| eyre!("encrypting recovery secret"))?;
        Ok(EncryptedSecret {
            protection: self.protection.clone(),
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedSecret, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if encrypted.protection != self.protection {
            bail!("recovery encryption configuration does not match");
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| eyre!("invalid recovery encryption key"))?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(encrypted.nonce),
                Payload {
                    msg: &encrypted.ciphertext,
                    aad,
                },
            )
            .map_err(|_| eyre!("incorrect recovery passphrase or tampered recovery data"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

impl EncryptedSecret {
    pub fn decrypt(&self, passphrase: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        UnlockedRecovery::derive(self.protection.clone(), passphrase)?.decrypt(self, aad)
    }
}

/// Bind each encrypted authorization value to its credential and recovery key.
pub fn credential_aad(credential_id: &[u8], public_blob: &[u8], policy_ref: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    ciborium::into_writer(
        &(
            "linux-tpm-fido2/recovery-auth/v1",
            credential_id,
            public_blob,
            policy_ref,
        ),
        &mut aad,
    )
    .expect("serializing recovery associated data");
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_encryption_rejects_wrong_password_tampering_and_slot_swaps() {
        let unlocked = UnlockedRecovery::new("a long test recovery phrase").unwrap();
        let config = unlocked.configuration().unwrap();
        assert!(UnlockedRecovery::unlock(&config, "wrong phrase").is_err());
        let unlocked = UnlockedRecovery::unlock(&config, "a long test recovery phrase").unwrap();
        let aad = credential_aad(b"credential-1", b"recovery-public", b"policy-ref");
        let secret = [0x42; 32];
        let encrypted = unlocked.encrypt(&secret, &aad).unwrap();
        assert_eq!(
            unlocked.decrypt(&encrypted, &aad).unwrap().as_slice(),
            secret
        );
        assert_ne!(
            encrypted.nonce,
            unlocked.encrypt(&secret, &aad).unwrap().nonce
        );
        let swapped = credential_aad(b"credential-2", b"recovery-public", b"policy-ref");
        assert!(unlocked.decrypt(&encrypted, &swapped).is_err());
        assert!(
            unlocked
                .decrypt(
                    &encrypted,
                    &credential_aad(b"credential-1", b"other-key", b"policy-ref")
                )
                .is_err()
        );
        assert!(
            unlocked
                .decrypt(
                    &encrypted,
                    &credential_aad(b"credential-1", b"recovery-public", b"other-ref")
                )
                .is_err()
        );
        let mut tampered = encrypted.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(unlocked.decrypt(&tampered, &aad).is_err());
        tampered = encrypted.clone();
        tampered.nonce[0] ^= 1;
        assert!(unlocked.decrypt(&tampered, &aad).is_err());
        tampered = encrypted;
        tampered.protection.memory_kib = u32::MAX;
        assert!(
            tampered
                .decrypt("a long test recovery phrase", &aad)
                .is_err()
        );
    }
}
