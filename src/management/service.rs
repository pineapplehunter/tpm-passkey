use std::{path::Path, sync::mpsc};

use ciborium::cbor;
use zeroize::Zeroize;

use super::{CredentialTarget, ManagementRequest, ManagementResponse};
use crate::{ctap2, store, tpm};

fn filter_uid(uid: u32) -> Option<u32> {
    if uid == 0 { None } else { Some(uid) }
}

fn check_pcr_stale(
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    policy: &store::StoredPcrPolicy,
) -> Option<bool> {
    let pcr_indices = tpm::pcr_indices_from_selection(&policy.selection).ok()?;
    let tx = tpm_cmd_tx?;
    let (digest_tx, digest_rx) = mpsc::channel();
    let cmd = ctap2::TpmCommand::PcrDigestCheck(ctap2::PcrDigestCheckCommand {
        pcr_indices,
        resp_tx: digest_tx,
    });
    let (resp_tx, resp_rx) = mpsc::channel();
    if tx.send((cmd, resp_tx)).is_err() {
        return None;
    }
    // Wait for the TPM command to complete.
    if resp_rx.recv().ok()?.is_err() {
        return None;
    }
    // Retrieve the current digest.
    let current_digest = digest_rx.recv().ok()?;
    match current_digest {
        Ok(d) => Some(d != policy.digest),
        Err(_) => None,
    }
}

fn handle_list_credentials(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    peer_uid: u32,
) -> ManagementResponse {
    match store::load_ctap2_credentials_from_dir(store_dir, filter_uid(peer_uid)) {
        Ok(credentials) => {
            let creds: Vec<ciborium::value::Value> = credentials
                .iter()
                .map(|c| {
                    let pcr_stale = c
                        .policy
                        .as_ref()
                        .and_then(|p| check_pcr_stale(tpm_cmd_tx, p));
                    cbor!({
                        "id" => hex::encode(&c.id),
                        "rp_id" => c.rp_id.as_str(),
                        "user_name" => c.user_name.as_deref().unwrap_or(""),
                        "discoverable" => c.discoverable,
                        "pcr_stale" => pcr_stale,
                    })
                    .unwrap()
                })
                .collect();
            ManagementResponse {
                ok: true,
                error: None,
                result: Some(cbor!({ "credentials" => creds }).unwrap()),
            }
        }
        Err(e) => ManagementResponse {
            ok: false,
            error: Some(format!("{e}")),
            result: None,
        },
    }
}
fn handle_update_passphrase(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    peer_uid: u32,
    old_passphrase: Option<&str>,
    new_passphrase: &str,
) -> ManagementResponse {
    // Validate or set the daemon passphrase.
    match store::load_daemon_passphrase_from_dir(store_dir) {
        Ok(Some((ref salt, ref hash, ref kdf))) => {
            let Some(old) = old_passphrase else {
                return ManagementResponse {
                    ok: false,
                    error: Some("daemon passphrase is already set; provide the current passphrase to change it".into()),
                    result: None,
                };
            };
            let mut computed = match tpm::recovery_passphrase_hash(kdf, salt, old) {
                Ok(h) => h,
                Err(e) => {
                    return ManagementResponse {
                        ok: false,
                        error: Some(format!("passphrase validation error: {e}")),
                        result: None,
                    };
                }
            };
            if computed != *hash {
                computed.zeroize();
                return ManagementResponse {
                    ok: false,
                    error: Some("current passphrase does not match".into()),
                    result: None,
                };
            }
            computed.zeroize();
        }
        Ok(None) => { /* first-time setup */ }
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("failed to check daemon passphrase: {e}")),
                result: None,
            };
        }
    }

    let mut new_salt = vec![0u8; 32];
    if getrandom::fill(&mut new_salt).is_err() {
        return ManagementResponse {
            ok: false,
            error: Some("failed to generate random salt".into()),
            result: None,
        };
    }
    let new_kdf = tpm::RecoveryKdf::argon2id_default();
    let new_hash = match tpm::recovery_passphrase_hash(&new_kdf, &new_salt, new_passphrase) {
        Ok(h) => h,
        Err(e) => {
            new_salt.zeroize();
            return ManagementResponse {
                ok: false,
                error: Some(format!("new passphrase hash error: {e}")),
                result: None,
            };
        }
    };

    if let Err(e) = store::save_daemon_passphrase_to_dir(store_dir, &new_salt, &new_hash, &new_kdf)
    {
        new_salt.zeroize();
        return ManagementResponse {
            ok: false,
            error: Some(format!("failed to save daemon passphrase: {e}")),
            result: None,
        };
    }

    // Update per-credential recovery passphrases to match the new daemon passphrase.
    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, filter_uid(peer_uid))
    {
        Ok(c) => c,
        Err(e) => {
            new_salt.zeroize();
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let mut results = Vec::new();
    for credential in &credentials {
        let id_hex = hex::encode(&credential.id);
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "no recovery slot",
                    })
                    .unwrap(),
                );
                continue;
            }
        };

        let recovery_key = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let cmd = ctap2::TpmCommand::PassphraseChange(ctap2::PassphraseChangeCommand {
                credential_id: credential.id.clone(),
                recovery_key,
                new_passphrase_hash: new_hash.clone(),
                new_salt: new_salt.clone(),
                new_kdf: new_kdf.clone(),
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            Err(color_eyre::eyre::eyre!(
                "TPM not available for recovery passphrase update"
            ))
        };

        match cmd_result {
            Ok(()) => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "ok",
                    })
                    .unwrap(),
                );
            }
            Err(e) => {
                log::warn!("failed to change passphrase for {id_hex}: {e}");
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => format!("{e}"),
                    })
                    .unwrap(),
                );
            }
        }
    }

    new_salt.zeroize();

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(
            cbor!({ "status" => "daemon passphrase updated", "results" => results }).unwrap(),
        ),
    }
}
fn handle_update_pcr_reference(
    store_dir: &Path,
    peer_uid: u32,
    passphrase: &str,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
) -> ManagementResponse {
    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, filter_uid(peer_uid))
    {
        Ok(c) => c,
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let mut results = Vec::new();
    for credential in &credentials {
        let id_hex = hex::encode(&credential.id);
        let policy = match credential.policy.as_ref() {
            Some(p) => p,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "no PCR policy",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "no recovery slot",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let policy_ref = match policy.policy_ref.as_ref() {
            Some(r) => r.clone(),
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => "credential has no policyRef",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let authority_name = match policy.authority_name.as_ref() {
            Some(n) => n.clone(),
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => "credential has no authority name",
                    })
                    .unwrap(),
                );
                continue;
            }
        };

        // Validate recovery passphrase (no TPM needed).
        let passphrase_result =
            tpm::recovery_passphrase_hash(&recovery.kdf, &recovery.passphrase_salt, passphrase);
        match passphrase_result {
            Ok(hash) => {
                if hash != recovery.passphrase_hash {
                    results.push(
                        cbor!({
                            "credential" => id_hex,
                            "status" => "error",
                            "error" => "recovery passphrase does not match",
                        })
                        .unwrap(),
                    );
                    continue;
                }
            }
            Err(e) => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => format!("passphrase validation error: {e}"),
                    })
                    .unwrap(),
                );
                continue;
            }
        }

        let authority = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        // Send TPM operation to main thread, or fall back to direct open.
        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let pcr_indices = match tpm::pcr_indices_from_selection(&policy.selection) {
                Ok(indices) => indices,
                Err(error) => {
                    results.push(
                        cbor!({
                            "credential" => id_hex,
                            "status" => "error",
                            "error" => format!("invalid stored PCR selection: {error}"),
                        })
                        .unwrap(),
                    );
                    continue;
                }
            };
            let cmd = ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: credential.id.clone(),
                pcr_indices,
                authority,
                authority_name,
                policy_ref,
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            // Fallback: open TPM directly (for testing without daemon).
            let pcr_indices = match tpm::pcr_indices_from_selection(&policy.selection) {
                Ok(indices) => indices,
                Err(error) => {
                    results.push(
                        cbor!({
                            "credential" => id_hex,
                            "status" => "error",
                            "error" => format!("invalid stored PCR selection: {error}"),
                        })
                        .unwrap(),
                    );
                    continue;
                }
            };
            ctap2::update_pcr_policy_for_credential(
                store_dir,
                None,
                &credential.id,
                passphrase,
                &pcr_indices,
            )
        };

        match cmd_result {
            Ok(()) => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "ok",
                    })
                    .unwrap(),
                );
            }
            Err(e) => {
                log::warn!("failed to update PCR policy for {id_hex}: {e}");
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => format!("{e}"),
                    })
                    .unwrap(),
                );
            }
        }
    }

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(cbor!({ "results" => results }).unwrap()),
    }
}

fn handle_update_pcr_policy(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    peer_uid: u32,
    passphrase: &str,
    pcr_indices: &[u32],
    credential_target: &CredentialTarget,
) -> ManagementResponse {
    if let Err(error) = tpm::pcr_selection_for_indices(pcr_indices) {
        return ManagementResponse {
            ok: false,
            error: Some(format!("invalid PCR selection: {error}")),
            result: None,
        };
    }

    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, filter_uid(peer_uid))
    {
        Ok(c) => c,
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let ids: Vec<Vec<u8>> = match credential_target {
        CredentialTarget::All { all: true } => credentials.iter().map(|c| c.id.clone()).collect(),
        CredentialTarget::All { all: false } => {
            return ManagementResponse {
                ok: false,
                error: Some("--all must be explicitly set to true".into()),
                result: None,
            };
        }
        CredentialTarget::Ids { credential_ids } => {
            match credential_ids
                .iter()
                .map(hex::decode)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(ids) => ids,
                Err(e) => {
                    return ManagementResponse {
                        ok: false,
                        error: Some(format!("invalid hex credential ID: {e}")),
                        result: None,
                    };
                }
            }
        }
    };

    let mut results = Vec::new();

    for id in &ids {
        let id_hex = hex::encode(id);
        let credential = match credentials.iter().find(|c| c.id == *id) {
            Some(c) => c,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "credential not found",
                    })
                    .unwrap(),
                );
                continue;
            }
        };

        let policy = match credential.policy.as_ref() {
            Some(p) => p,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "no PCR policy",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "skipped",
                        "reason" => "no recovery slot",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let policy_ref = match policy.policy_ref.as_ref() {
            Some(r) => r.clone(),
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => "credential has no policyRef",
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let authority_name = match policy.authority_name.as_ref() {
            Some(n) => n.clone(),
            None => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => "credential has no authority name",
                    })
                    .unwrap(),
                );
                continue;
            }
        };

        // Validate passphrase (no TPM needed).
        let mut passphrase_hash = match tpm::recovery_passphrase_hash(
            &recovery.kdf,
            &recovery.passphrase_salt,
            passphrase,
        ) {
            Ok(h) => h,
            Err(e) => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => format!("passphrase validation error: {e}"),
                    })
                    .unwrap(),
                );
                continue;
            }
        };
        let passphrase_ok = passphrase_hash == recovery.passphrase_hash;
        passphrase_hash.zeroize();
        if !passphrase_ok {
            results.push(
                cbor!({
                    "credential" => id_hex,
                    "status" => "error",
                    "error" => "recovery passphrase does not match",
                })
                .unwrap(),
            );
            continue;
        }

        let authority = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        // Send TPM operation to main thread, or fall back to direct open.
        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let cmd = ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: id.clone(),
                pcr_indices: pcr_indices.to_vec(),
                authority,
                authority_name,
                policy_ref,
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            // Fallback: open TPM directly (for testing without daemon).
            ctap2::update_pcr_policy_for_credential(
                store_dir,
                Some(Path::new("/dev/tpmrm0")),
                id,
                passphrase,
                pcr_indices,
            )
        };

        match cmd_result {
            Ok(()) => {
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "ok",
                    })
                    .unwrap(),
                );
            }
            Err(e) => {
                log::warn!("failed to update PCR policy for {id_hex}: {e}");
                results.push(
                    cbor!({
                        "credential" => id_hex,
                        "status" => "error",
                        "error" => format!("{e}"),
                    })
                    .unwrap(),
                );
            }
        }
    }

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(cbor!({ "results" => results }).unwrap()),
    }
}

fn handle_set_default_pcr_policy(store_dir: &Path, pcr_indices: &[u32]) -> ManagementResponse {
    if let Err(error) = tpm::pcr_selection_for_indices(pcr_indices) {
        return ManagementResponse {
            ok: false,
            error: Some(format!("invalid PCR selection: {error}")),
            result: None,
        };
    }
    match store::save_default_pcr_policy(store_dir, pcr_indices) {
        Ok(()) => ManagementResponse {
            ok: true,
            error: None,
            result: Some(cbor!({ "pcr_indices" => pcr_indices }).unwrap()),
        },
        Err(e) => ManagementResponse {
            ok: false,
            error: Some(format!("{e}")),
            result: None,
        },
    }
}

pub(super) fn dispatch(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    peer_uid: u32,
    request: &ManagementRequest,
) -> ManagementResponse {
    match request {
        ManagementRequest::ListCredentials => {
            handle_list_credentials(store_dir, tpm_cmd_tx, peer_uid)
        }
        ManagementRequest::UpdatePassphrase {
            old_passphrase,
            new_passphrase,
        } => handle_update_passphrase(
            store_dir,
            tpm_cmd_tx,
            peer_uid,
            old_passphrase.as_deref(),
            new_passphrase,
        ),
        ManagementRequest::UpdatePcrReference { passphrase } => {
            handle_update_pcr_reference(store_dir, peer_uid, passphrase, tpm_cmd_tx)
        }
        ManagementRequest::UpdatePcrPolicy {
            passphrase,
            pcr_indices,
            credential_target,
        } => handle_update_pcr_policy(
            store_dir,
            tpm_cmd_tx,
            peer_uid,
            passphrase,
            pcr_indices,
            credential_target,
        ),
        ManagementRequest::SetDefaultPcrPolicy { pcr_indices } => {
            handle_set_default_pcr_policy(store_dir, pcr_indices)
        }
    }
}
