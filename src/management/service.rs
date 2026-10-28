use std::{collections::HashMap, path::Path, sync::mpsc};

use ciborium::{cbor, value::Value};
use color_eyre::{
    Result,
    eyre::{WrapErr, eyre},
};
use zeroize::Zeroizing;

use super::{CredentialTarget, ManagementRequest, ManagementResponse};
use crate::{ctap2, store, tpm};

fn execute(tx: Option<&ctap2::TpmCmdSender>, command: ctap2::TpmCommand) -> Result<()> {
    let tx = tx.ok_or_else(|| eyre!("authenticator worker is not available"))?;
    let (response_tx, response_rx) = mpsc::channel();
    tx.send((command, response_tx))
        .map_err(|_| eyre!("authenticator worker channel closed"))?;
    response_rx
        .recv()
        .wrap_err("waiting for authenticator worker")?
        .map_err(|error| eyre!("{error}"))
}

fn check_pcr_stale(
    tx: Option<&ctap2::TpmCmdSender>,
    policy: &store::StoredPcrPolicy,
) -> Option<bool> {
    let pcr_indices = tpm::pcr_indices_from_selection(&policy.selection).ok()?;
    let (resp_tx, resp_rx) = mpsc::channel();
    execute(
        tx,
        ctap2::TpmCommand::PcrDigestCheck(ctap2::PcrDigestCheckCommand {
            pcr_indices,
            resp_tx,
        }),
    )
    .ok()?;
    Some(resp_rx.recv().ok()?.ok()? != policy.digest)
}

fn list_credentials(store_dir: &Path, tx: Option<&ctap2::TpmCmdSender>) -> Result<Value> {
    let credentials = store::load_ctap2_credentials_from_dir(store_dir)?;
    let summaries: HashMap<_, _> = store::load_credential_summaries_from_dir(store_dir)?
        .into_iter()
        .map(|summary| (summary.id.clone(), summary))
        .collect();
    let mut creds = Vec::with_capacity(credentials.len());
    for credential in &credentials {
        let summary = summaries
            .get(&credential.id)
            .ok_or_else(|| eyre!("credential is missing listing metadata"))?;
        let pcr_stale = credential
            .policy
            .as_ref()
            .and_then(|policy| check_pcr_stale(tx, policy));
        let pcr_indices = summary
            .policy_selection
            .as_deref()
            .and_then(|selection| tpm::pcr_indices_from_selection(selection).ok())
            .unwrap_or_default();
        creds.push(
            cbor!({
                "id" => hex::encode(&credential.id),
                "rp_id" => credential.rp_id.as_str(),
                "user_name" => credential.user_name.as_deref().unwrap_or(""),
                "discoverable" => credential.discoverable,
                "registered_at" => summary.registered_at.as_str(),
                "last_used_at" => summary.last_used_at.as_deref(),
                "pcr_indices" => pcr_indices,
                "pcr_stale" => pcr_stale,
            })
            .unwrap(),
        );
    }
    Ok(cbor!({ "credentials" => creds }).unwrap())
}

fn update_pcr_policies(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    passphrase: &str,
    new_indices: Option<&[u32]>,
    target: Option<&CredentialTarget>,
) -> Result<Value> {
    if let Some(indices) = new_indices {
        tpm::pcr_selection_for_indices(indices)?;
    }
    let credentials = store::load_ctap2_credentials_from_dir(store_dir)?;
    let ids = match target {
        None | Some(CredentialTarget::All { all: true }) => credentials
            .iter()
            .map(|credential| credential.id.clone())
            .collect(),
        Some(CredentialTarget::All { all: false }) => {
            return Err(eyre!("--all must be explicitly set to true"));
        }
        Some(CredentialTarget::Ids { credential_ids }) => credential_ids
            .iter()
            .map(hex::decode)
            .collect::<std::result::Result<Vec<_>, _>>(
        )?,
    };
    let mut results = Vec::new();
    for id in ids {
        let id_hex = hex::encode(&id);
        let credential = credentials.iter().find(|credential| credential.id == id);
        let reason = match credential {
            None => Some("credential not found"),
            Some(credential) if credential.policy.is_none() => Some("no PCR policy"),
            Some(credential) if credential.recovery.is_none() => Some("no recovery slot"),
            _ => None,
        };
        if let Some(reason) = reason {
            results.push(
                cbor!({ "credential" => id_hex, "status" => "skipped", "reason" => reason })
                    .unwrap(),
            );
            continue;
        }
        let credential = credential.expect("checked credential");
        let pcr_indices = match new_indices {
            Some(indices) => indices.to_vec(),
            None => {
                tpm::pcr_indices_from_selection(&credential.policy.as_ref().unwrap().selection)?
            }
        };
        // The worker decrypts the slot using this request's phrase. An unlocked
        // enrollment cache never authorizes a PCR-policy update.
        let result = execute(
            tx,
            ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: id,
                pcr_indices,
                passphrase: Zeroizing::new(passphrase.to_owned()),
            }),
        );
        results.push(match result {
            Ok(()) => cbor!({ "credential" => id_hex, "status" => "ok" }).unwrap(),
            Err(error) => {
                cbor!({ "credential" => id_hex, "status" => "error", "error" => error.to_string() })
                    .unwrap()
            }
        });
    }
    Ok(cbor!({ "results" => results }).unwrap())
}

fn dispatch_result(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
) -> Result<Value> {
    match request {
        ManagementRequest::ListCredentials => list_credentials(store_dir, tx),
        ManagementRequest::UpdatePassphrase {
            old_passphrase,
            new_passphrase,
        } => {
            execute(
                tx,
                ctap2::TpmCommand::SetRecoveryPassphrase {
                    old_passphrase: old_passphrase
                        .as_ref()
                        .map(|phrase| Zeroizing::new(phrase.clone())),
                    new_passphrase: Zeroizing::new(new_passphrase.clone()),
                },
            )?;
            Ok(cbor!({ "status" => "recovery passphrase updated" }).unwrap())
        }
        ManagementRequest::UnlockRecovery { passphrase } => {
            execute(
                tx,
                ctap2::TpmCommand::UnlockRecovery {
                    passphrase: Zeroizing::new(passphrase.clone()),
                },
            )?;
            Ok(cbor!({ "status" => "recovery enrollment unlocked" }).unwrap())
        }
        ManagementRequest::UpdatePcrReference { passphrase } => {
            update_pcr_policies(store_dir, tx, passphrase, None, None)
        }
        ManagementRequest::UpdatePcrPolicy {
            passphrase,
            pcr_indices,
            credential_target,
        } => update_pcr_policies(
            store_dir,
            tx,
            passphrase,
            Some(pcr_indices),
            Some(credential_target),
        ),
        ManagementRequest::SetDefaultPcrPolicy { pcr_indices } => {
            tpm::pcr_selection_for_indices(pcr_indices)?;
            store::save_default_pcr_policy(store_dir, pcr_indices)?;
            Ok(cbor!({ "pcr_indices" => pcr_indices }).unwrap())
        }
        ManagementRequest::ShowConfig => {
            let default_pcr_policy =
                store::load_default_pcr_policy(store_dir)?.unwrap_or_else(|| vec![7]);
            let recovery_passphrase_configured = store::load_recovery_config(store_dir)?.is_some();
            Ok(cbor!({
                "default_pcr_policy" => default_pcr_policy,
                "recovery_passphrase_configured" => recovery_passphrase_configured,
            })
            .unwrap())
        }
    }
}

pub(super) fn dispatch(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
) -> ManagementResponse {
    match dispatch_result(store_dir, tx, request) {
        Ok(result) => ManagementResponse {
            ok: true,
            error: None,
            result: Some(result),
        },
        Err(error) => ManagementResponse {
            ok: false,
            error: Some(error.to_string()),
            result: None,
        },
    }
}
