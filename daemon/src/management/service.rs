use std::{collections::HashMap, path::Path, sync::mpsc, time::Instant};

use ciborium::{cbor, value::Value};
use color_eyre::{Result, eyre::eyre};
use zeroize::Zeroizing;

use super::{CredentialTarget, ManagementError, ManagementRequest, ManagementResponse};
use crate::{ctap2, store, tpm};

fn execute(
    tx: Option<&ctap2::TpmCmdSender>,
    command: ctap2::TpmCommand,
    deadline: Instant,
) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(ManagementError::Timeout.into());
    }
    let tx = tx.ok_or(ManagementError::WorkerUnavailable)?;
    let (response_tx, response_rx) = mpsc::channel();
    tx.send((
        ctap2::TpmCommand::BeforeDeadline {
            deadline,
            command: Box::new(command),
        },
        response_tx,
    ))
    .map_err(|_| ManagementError::WorkerUnavailable)?;
    response_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => ManagementError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => ManagementError::WorkerUnavailable,
        })?
        .map_err(Into::into)
}

fn check_pcr_stale(
    tx: Option<&ctap2::TpmCmdSender>,
    policy: &store::StoredPcrPolicy,
    deadline: Instant,
) -> Option<bool> {
    let pcr_indices = tpm::pcr_indices_from_selection(&policy.selection).ok()?;
    let (resp_tx, resp_rx) = mpsc::channel();
    execute(
        tx,
        ctap2::TpmCommand::PcrDigestCheck(ctap2::PcrDigestCheckCommand {
            pcr_indices,
            resp_tx,
        }),
        deadline,
    )
    .ok()?;
    Some(
        resp_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()?
            .ok()?
            != policy.digest,
    )
}

fn list_credentials(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    deadline: Instant,
) -> Result<Value> {
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
            .and_then(|policy| check_pcr_stale(tx, policy, deadline));
        let pcr_indices = summary
            .policy_selection
            .as_deref()
            .and_then(|selection| tpm::pcr_indices_from_selection(selection).ok())
            .unwrap_or_default();
        creds.push(
            cbor!({
                "id" => hex::encode(&credential.id),
                "local_id" => summary.local_id,
                "rp_id" => credential.rp_id.as_str(),
                "user_name" => credential.user_name.as_deref().unwrap_or(""),
                "user_display_name" => credential.user_display_name.as_deref().unwrap_or(""),
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

fn credential_info(store_dir: &Path, local_id: u64) -> Result<Value> {
    let summaries = store::load_credential_summaries_from_dir(store_dir)?;
    let summary = summaries
        .iter()
        .find(|summary| u64::try_from(summary.local_id).ok() == Some(local_id))
        .ok_or(ManagementError::NotFound)?;
    let credential = store::load_ctap2_credentials_from_dir(store_dir)?
        .into_iter()
        .find(|credential| credential.id == summary.id)
        .ok_or_else(|| eyre!("credential metadata is inconsistent"))?;
    let pcr_indices = credential
        .policy
        .as_ref()
        .and_then(|policy| tpm::pcr_indices_from_selection(&policy.selection).ok());
    let policy = credential.policy.as_ref();
    let migration = credential.migration_authority.as_ref();
    Ok(cbor!({
        "local_id" => local_id,
        "credential_id" => hex::encode(&credential.id),
        "rp_id" => credential.rp_id.as_str(),
        "user_handle" => hex::encode(&credential.user_handle),
        "user_name" => credential.user_name.as_deref(),
        "user_display_name" => credential.user_display_name.as_deref(),
        "discoverable" => credential.discoverable,
        "signature_count" => credential.sign_count,
        "created_at" => summary.registered_at.as_str(),
        "last_used_at" => summary.last_used_at.as_deref(),
        "credential_public_key_x" => hex::encode(&credential.key.public_key_x),
        "credential_public_key_y" => hex::encode(&credential.key.public_key_y),
        "pcr_policy" => policy.is_some_and(|policy| policy.selection != "none"),
        "pcr_indices" => pcr_indices,
        "pcr_digest" => policy.map(|p| hex::encode(&p.digest)),
        "pcr_policy_ref" => policy.and_then(|p| p.policy_ref.as_ref()).map(hex::encode),
        "pcr_authority_name" => policy.and_then(|p| p.authority_name.as_ref()).map(hex::encode),
        "pcr_authority_signature" => policy.and_then(|p| p.authority_signature.as_ref()).map(hex::encode),
        "pcr_policy_version" => policy.map(|p| p.policy_version),
        "migration_configured" => migration.is_some(),
        "migration_label" => migration.and_then(|m| m.label.as_deref()),
        "migration_last_used_at" => migration.and_then(|m| m.last_used.as_deref()),
        "migration_use_count" => migration.map(|m| m.used_count),
        "migration_public_key_x" => migration.map(|m| hex::encode(&m.key.public_key_x)),
        "migration_public_key_y" => migration.map(|m| hex::encode(&m.key.public_key_y)),
    }).unwrap())
}

fn update_pcr_policies(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    passphrase: &str,
    new_indices: Option<&[u32]>,
    target: Option<&CredentialTarget>,
    skip_pcr_disabled: bool,
    default_policy_change: &super::DefaultPcrPolicyChange,
    deadline: Instant,
) -> Result<Value> {
    if let Some(indices) = new_indices.filter(|indices| !indices.is_empty()) {
        tpm::pcr_selection_for_indices(indices).map_err(|_| ManagementError::InvalidPolicy)?;
    }
    if let super::DefaultPcrPolicyChange::Set { pcr_indices } = default_policy_change {
        tpm::pcr_selection_for_indices(pcr_indices).map_err(|_| ManagementError::InvalidPolicy)?;
    }

    // Authentication and configuration checks are independent of the target
    // list, including an empty store or a client selecting no credentials.
    let _guard = store::credential_mutation_guard_until(deadline)?;
    if matches!(
        default_policy_change,
        super::DefaultPcrPolicyChange::Set { .. }
    ) && store::load_migration_config(store_dir)?.is_none()
    {
        return Err(ManagementError::SetupRequired.into());
    }
    execute(
        tx,
        ctap2::TpmCommand::VerifyMigrationPassphrase {
            passphrase: Zeroizing::new(passphrase.to_owned()),
        },
        deadline,
    )?;

    // The snapshot and every update/default mutation belong to this one locked
    // request, so "all" never means a stale client-side list.
    let credentials = store::load_ctap2_credentials_from_dir(store_dir)?;
    let ids: Vec<Vec<u8>> = match target {
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
    let mut results = Vec::with_capacity(ids.len());
    let mut all_succeeded = true;
    for id in ids {
        let id_hex = hex::encode(&id);
        if Instant::now() >= deadline {
            all_succeeded = false;
            results.push(cbor!({"credential" => id_hex, "status" => "timeout", "error" => "not attempted before deadline"}).unwrap());
            continue;
        }
        let credential = credentials.iter().find(|credential| credential.id == id);
        let is_pcr_disabled = credential.is_some_and(|credential| {
            credential
                .policy
                .as_ref()
                .is_none_or(|policy| policy.selection == "none")
        });
        if skip_pcr_disabled && is_pcr_disabled {
            results.push(cbor!({"credential" => id_hex, "status" => "skipped", "reason" => "PCR policy disabled"}).unwrap());
            continue;
        }
        if credential.is_none() {
            all_succeeded = false;
            results.push(cbor!({"credential" => id_hex, "status" => "error", "error" => "credential not found"}).unwrap());
            continue;
        }
        let credential = credential.expect("checked credential");
        let pcr_indices = match new_indices {
            Some(indices) if indices.is_empty() => None,
            Some(indices) => Some(indices.to_vec()),
            None => credential
                .policy
                .as_ref()
                .and_then(|policy| tpm::pcr_indices_from_selection(&policy.selection).ok()),
        };
        let result = execute(
            tx,
            ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: id,
                pcr_indices,
                passphrase: Zeroizing::new(passphrase.to_owned()),
            }),
            deadline,
        );
        match result {
            Ok(()) => results.push(cbor!({"credential" => id_hex, "status" => "ok"}).unwrap()),
            Err(error) => {
                all_succeeded = false;
                let timed_out = Instant::now() >= deadline
                    || ManagementError::from_report(&error) == ManagementError::Timeout;
                let status = if timed_out { "timeout" } else { "error" };
                let error = if timed_out {
                    "outcome unknown after deadline; inspect current state before retrying"
                        .to_owned()
                } else {
                    ManagementError::from_report(&error).to_string()
                };
                results.push(
                    cbor!({"credential" => id_hex, "status" => status, "error" => error}).unwrap(),
                );
            }
        }
    }

    let default_updated = if all_succeeded && Instant::now() < deadline {
        match default_policy_change {
            super::DefaultPcrPolicyChange::Keep => false,
            super::DefaultPcrPolicyChange::Set { pcr_indices } => {
                store::save_default_pcr_policy(store_dir, pcr_indices)?;
                true
            }
            super::DefaultPcrPolicyChange::Disable => {
                store::clear_default_pcr_policy(store_dir)?;
                true
            }
        }
    } else {
        false
    };
    Ok(cbor!({"results" => results, "default_updated" => default_updated}).unwrap())
}

fn dispatch_result(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
    deadline: Instant,
) -> Result<Value> {
    if Instant::now() >= deadline {
        return Err(ManagementError::Timeout.into());
    }
    match request {
        ManagementRequest::ListCredentials => list_credentials(store_dir, tx, deadline),
        ManagementRequest::CredentialInfo { local_id } => credential_info(store_dir, *local_id),
        ManagementRequest::SetupMigration {
            passphrase,
            pcr_indices,
        } => {
            let _guard = store::credential_mutation_guard_until(deadline)?;
            if store::load_migration_config(store_dir)?.is_some() {
                return Err(ManagementError::AlreadyConfigured.into());
            }
            if !store::load_ctap2_credentials_from_dir(store_dir)?.is_empty() {
                return Err(ManagementError::CredentialsRemain.into());
            }
            if let Some(indices) = pcr_indices {
                tpm::pcr_selection_for_indices(indices)
                    .map_err(|_| ManagementError::InvalidPolicy)?;
            }
            let config = crate::migration_crypto::create_configuration(passphrase.as_str())
                .map_err(|error| eyre!("creating migration configuration: {error}"))?;
            if Instant::now() >= deadline {
                return Err(ManagementError::Timeout.into());
            }
            store::save_migration_setup(store_dir, &config, pcr_indices.as_deref())?;
            Ok(cbor!({"status" => "migration configured", "pcr_indices" => pcr_indices}).unwrap())
        }
        ManagementRequest::MigrateCredentials {
            passphrase,
            pcr_indices,
            credential_ids,
            all_credentials,
            default_policy_change,
        } => {
            if credential_ids.len() > 128 || credential_ids.iter().any(|id| id.len() > 2048) {
                return Err(eyre!("migration credential target exceeds input limits"));
            }
            let target = if *all_credentials {
                CredentialTarget::All { all: true }
            } else {
                CredentialTarget::Ids {
                    credential_ids: credential_ids.clone(),
                }
            };
            update_pcr_policies(
                store_dir,
                tx,
                passphrase,
                pcr_indices.as_deref(),
                Some(&target),
                true,
                default_policy_change,
                deadline,
            )
        }
        ManagementRequest::UpdateMigrationPassphrase {
            old_passphrase,
            new_passphrase,
        } => {
            let _guard = store::credential_mutation_guard_until(deadline)?;
            execute(
                tx,
                ctap2::TpmCommand::SetMigrationPassphrase {
                    old_passphrase: old_passphrase.clone(),
                    new_passphrase: new_passphrase.clone(),
                },
                deadline,
            )?;
            Ok(cbor!({ "status" => "migration passphrase updated" }).unwrap())
        }
        ManagementRequest::VerifyMigrationPassphrase { passphrase } => {
            execute(
                tx,
                ctap2::TpmCommand::VerifyMigrationPassphrase {
                    passphrase: passphrase.clone(),
                },
                deadline,
            )?;
            Ok(cbor!({ "status" => "migration passphrase verified; enrollment does not require unlock" }).unwrap())
        }
        ManagementRequest::MigratePcrReference { passphrase } => update_pcr_policies(
            store_dir,
            tx,
            passphrase,
            None,
            None,
            true,
            &super::DefaultPcrPolicyChange::Keep,
            deadline,
        ),
        ManagementRequest::UpdatePcrPolicy {
            passphrase,
            pcr_indices,
            credential_target,
            default_policy_change,
        } => update_pcr_policies(
            store_dir,
            tx,
            passphrase,
            Some(pcr_indices),
            Some(credential_target),
            false,
            default_policy_change,
            deadline,
        ),
        ManagementRequest::SetDefaultPcrPolicy { pcr_indices } => {
            let _guard = store::credential_mutation_guard_until(deadline)?;
            tpm::pcr_selection_for_indices(pcr_indices)
                .map_err(|_| ManagementError::InvalidPolicy)?;
            if store::load_migration_config(store_dir)?.is_none() {
                return Err(ManagementError::SetupRequired.into());
            }
            store::save_default_pcr_policy(store_dir, pcr_indices)?;
            Ok(cbor!({ "pcr_indices" => pcr_indices }).unwrap())
        }
        ManagementRequest::DisableDefaultPcrPolicy => {
            let _guard = store::credential_mutation_guard_until(deadline)?;
            store::clear_default_pcr_policy(store_dir)?;
            Ok(cbor!({ "status" => "PCR binding disabled for future registrations" }).unwrap())
        }
        ManagementRequest::ShowConfig => {
            let default_pcr_policy = store::load_default_pcr_policy(store_dir)?;
            let migration_configured = store::load_migration_config(store_dir)?.is_some();
            Ok(cbor!({
                "default_pcr_policy" => default_pcr_policy,
                "migration_configured" => migration_configured,
            })
            .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    fn mock_worker(result: ctap2::TpmCmdResult) -> ctap2::TpmCmdSender {
        let (tx, rx) = mpsc::channel::<(ctap2::TpmCommand, mpsc::Sender<ctap2::TpmCmdResult>)>();
        std::thread::spawn(move || {
            while let Ok((command, reply)) = rx.recv() {
                let _ = reply.send(result.clone());
                drop(command);
            }
        });
        tx
    }

    fn test_credential(
        id: Vec<u8>,
        policy: Option<store::StoredPcrPolicy>,
    ) -> store::StoredCtap2Credential {
        let secret = p256::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let point = secret.public_key().to_sec1_point(false);
        store::StoredCtap2Credential {
            id,
            rp_id: "example.test".into(),
            discoverable: true,
            user_handle: vec![1],
            user_name: None,
            user_display_name: None,
            key: store::StoredTpmKey {
                private: vec![1],
                public: vec![1],
                public_key_x: point.x().unwrap().to_vec(),
                public_key_y: point.y().unwrap().to_vec(),
            },
            policy,
            migration_authority: None,
            sign_count: 0,
            integrity_mac: None,
        }
    }

    #[test]
    fn registration_side_mutation_guard_never_waits_for_management() {
        let _guard = store::credential_mutation_guard_until(
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .unwrap();
        assert!(store::try_credential_mutation_guard().is_err());
    }

    #[test]
    fn every_mutation_lock_wait_obeys_deadline_without_sending_or_writing() {
        let dir = std::env::temp_dir().join(format!("lock-deadline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _guard = store::credential_mutation_guard_until(
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();
        for request in [
            ManagementRequest::SetupMigration {
                passphrase: Zeroizing::new("never persist this".into()),
                pcr_indices: None,
            },
            ManagementRequest::UpdateMigrationPassphrase {
                old_passphrase: None,
                new_passphrase: Zeroizing::new("never persist this".into()),
            },
            ManagementRequest::SetDefaultPcrPolicy {
                pcr_indices: vec![7],
            },
            ManagementRequest::DisableDefaultPcrPolicy,
            ManagementRequest::UpdatePcrPolicy {
                passphrase: Zeroizing::new("secret".into()),
                pcr_indices: vec![7],
                credential_target: CredentialTarget::All { all: true },
                default_policy_change: super::super::DefaultPcrPolicyChange::Keep,
            },
            ManagementRequest::MigratePcrReference {
                passphrase: Zeroizing::new("secret".into()),
            },
        ] {
            let start = Instant::now();
            let response = dispatch_until(
                &dir,
                Some(&tx),
                &request,
                start + std::time::Duration::from_millis(20),
            );
            assert!(!response.ok);
            assert_eq!(
                response.error.as_deref(),
                Some(ManagementError::Timeout.to_string().as_str())
            );
            assert!(start.elapsed() < std::time::Duration::from_millis(250));
            assert!(rx.try_recv().is_err(), "expired request sent a TPM command");
            assert!(!dir.exists(), "expired request touched persistent state");
        }
    }

    #[test]
    fn errors_are_actionable_but_do_not_forward_worker_or_storage_details() {
        let dir = std::env::temp_dir().join(format!("safe-errors-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let missing = dispatch(
            &dir,
            None,
            &ManagementRequest::SetDefaultPcrPolicy {
                pcr_indices: vec![7],
            },
        );
        assert_eq!(
            missing.error,
            Some(ManagementError::SetupRequired.to_string())
        );
        for error in [
            ManagementError::Authentication,
            ManagementError::Integrity,
            ManagementError::SetupRequired,
        ] {
            let tx = mock_worker(Err(error));
            let response = dispatch(
                &dir,
                Some(&tx),
                &ManagementRequest::VerifyMigrationPassphrase {
                    passphrase: Zeroizing::new("DO NOT LEAK THIS PASSPHRASE".into()),
                },
            );
            assert_eq!(response.error, Some(error.to_string()));
            assert!(!response.error.unwrap().contains("DO NOT LEAK"));
        }
        let private_report = eyre!("database ciphertext, path and passphrase DO NOT LEAK");
        assert_eq!(
            ManagementError::from_report(&private_report),
            ManagementError::Failed
        );
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("secret".into()),
                    pcr_indices: None
                }
            )
            .ok
        );
        // A malformed authenticated config is a safe integrity error too, not a
        // CBOR decoder dump containing database contents.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let options = sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(dir.join("credentials.sqlite"));
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options)
                    .await?;
                sqlx::query(
                    "UPDATE daemon_config SET value = X'00' WHERE key = 'migration_encryption'",
                )
                .execute(&pool)
                .await?;
                pool.close().await;
                Ok::<(), color_eyre::Report>(())
            })
            .unwrap();
        let response = dispatch(&dir, None, &ManagementRequest::ShowConfig);
        assert_eq!(response.error, Some(ManagementError::Integrity.to_string()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn worker_reply_wait_is_bounded_and_queued_command_has_original_deadline() {
        let (tx, rx) = mpsc::channel();
        let deadline = Instant::now() + std::time::Duration::from_millis(30);
        let start = Instant::now();
        assert!(
            execute(
                Some(&tx),
                ctap2::TpmCommand::VerifyMigrationPassphrase {
                    passphrase: Zeroizing::new("secret".into())
                },
                deadline
            )
            .is_err()
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
        let (command, _) = rx.try_recv().unwrap();
        assert!(
            matches!(command, ctap2::TpmCommand::BeforeDeadline { deadline: queued, .. } if queued == deadline)
        );
    }

    #[test]
    fn migration_setup_is_one_time_authenticated_and_reports_status() {
        let dir = std::env::temp_dir().join(format!("migration-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let response = dispatch(
            &dir,
            None,
            &ManagementRequest::SetupMigration {
                passphrase: Zeroizing::new("setup phrase".into()),
                pcr_indices: Some(vec![7]),
            },
        );
        assert!(response.ok);
        assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), Some(vec![7]));
        assert!(store::load_migration_config(&dir).unwrap().is_some());
        assert!(
            !dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("another".into()),
                    pcr_indices: None,
                }
            )
            .ok
        );
        let shown = dispatch(&dir, None, &ManagementRequest::ShowConfig);
        let result = shown.result.unwrap();
        assert_eq!(
            crate::management::value_get(&result, "migration_configured")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn migration_skips_pcr_disabled_credentials_but_all_policy_update_visits_them() {
        let dir = std::env::temp_dir().join(format!("disabled-credential-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("setup phrase".into()),
                    pcr_indices: None,
                },
            )
            .ok
        );
        store::save_ctap2_credentials_to_dir(&dir, &[test_credential(vec![1], None)]).unwrap();
        let tx = mock_worker(Ok(()));
        let migrated = dispatch(
            &dir,
            Some(&tx),
            &ManagementRequest::MigrateCredentials {
                passphrase: Zeroizing::new("migration phrase".into()),
                pcr_indices: Some(vec![7]),
                credential_ids: vec![],
                all_credentials: true,
                default_policy_change: super::super::DefaultPcrPolicyChange::Keep,
            },
        );
        let results = crate::management::value_get(migrated.result.as_ref().unwrap(), "results")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            crate::management::value_get(&results[0], "status")
                .unwrap()
                .as_text(),
            Some("skipped")
        );

        let updated = dispatch(
            &dir,
            Some(&tx),
            &ManagementRequest::UpdatePcrPolicy {
                passphrase: Zeroizing::new("migration phrase".into()),
                pcr_indices: vec![7],
                credential_target: CredentialTarget::All { all: true },
                default_policy_change: super::super::DefaultPcrPolicyChange::Keep,
            },
        );
        let results = crate::management::value_get(updated.result.as_ref().unwrap(), "results")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            crate::management::value_get(&results[0], "status")
                .unwrap()
                .as_text(),
            Some("ok")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn timed_out_policy_update_reports_partial_outcomes_without_changing_default() {
        let dir = std::env::temp_dir().join(format!("policy-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("setup phrase".into()),
                    pcr_indices: None,
                },
            )
            .ok
        );
        let policy = Some(store::StoredPcrPolicy {
            selection: "sha256:7".into(),
            digest: vec![1; 32],
            policy_ref: Some(vec![1]),
            authority_name: Some(vec![1]),
            authority_signature: Some(vec![1]),
            policy_version: 1,
        });
        store::save_ctap2_credentials_to_dir(
            &dir,
            &[
                test_credential(vec![1], policy.clone()),
                test_credential(vec![2], policy),
            ],
        )
        .unwrap();
        store::save_default_pcr_policy(&dir, &[1, 7]).unwrap();

        let (tx, rx) = mpsc::channel::<(ctap2::TpmCommand, mpsc::Sender<ctap2::TpmCmdResult>)>();
        std::thread::spawn(move || {
            let mut updates = 0;
            while let Ok((command, reply)) = rx.recv() {
                let command = match command {
                    ctap2::TpmCommand::BeforeDeadline { command, .. } => *command,
                    command => command,
                };
                if matches!(command, ctap2::TpmCommand::PcrPolicyUpdate(_)) {
                    updates += 1;
                    if updates == 2 {
                        let _ = reply.send(Err(ManagementError::Timeout));
                        continue;
                    }
                }
                let _ = reply.send(Ok(()));
            }
        });
        let result = dispatch_result(
            &dir,
            Some(&tx),
            &ManagementRequest::UpdatePcrPolicy {
                passphrase: Zeroizing::new("migration phrase".into()),
                pcr_indices: vec![1],
                credential_target: CredentialTarget::All { all: true },
                default_policy_change: super::super::DefaultPcrPolicyChange::Set {
                    pcr_indices: vec![7],
                },
            },
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .expect("policy update should return partial outcomes");
        let results = crate::management::value_get(&result, "results")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            crate::management::value_get(&results[0], "status")
                .unwrap()
                .as_text(),
            Some("ok")
        );
        assert_eq!(
            crate::management::value_get(&results[1], "status")
                .unwrap()
                .as_text(),
            Some("timeout")
        );
        assert_eq!(
            crate::management::value_get(&result, "default_updated")
                .unwrap()
                .as_bool(),
            Some(false)
        );
        assert_eq!(
            store::load_default_pcr_policy(&dir).unwrap(),
            Some(vec![1, 7])
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn migration_does_not_change_default_when_a_selected_credential_is_missing() {
        let dir = std::env::temp_dir().join(format!("migration-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("setup phrase".into()),
                    pcr_indices: None,
                },
            )
            .ok
        );
        let tx = mock_worker(Ok(()));
        let response = dispatch(
            &dir,
            Some(&tx),
            &ManagementRequest::MigrateCredentials {
                passphrase: Zeroizing::new("migration phrase".into()),
                pcr_indices: Some(vec![7]),
                credential_ids: vec!["deadbeef".into()],
                all_credentials: false,
                default_policy_change: super::super::DefaultPcrPolicyChange::Set {
                    pcr_indices: vec![7],
                },
            },
        );
        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(
            crate::management::value_get(&result, "default_updated")
                .unwrap()
                .as_bool(),
            Some(false)
        );
        assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn default_policy_can_be_set_or_disabled_with_no_credentials_after_authentication() {
        let dir = std::env::temp_dir().join(format!("empty-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("setup phrase".into()),
                    pcr_indices: None,
                },
            )
            .ok
        );

        let tx = mock_worker(Ok(()));
        for change in [
            super::super::DefaultPcrPolicyChange::Set {
                pcr_indices: vec![7],
            },
            super::super::DefaultPcrPolicyChange::Disable,
        ] {
            let response = dispatch(
                &dir,
                Some(&tx),
                &ManagementRequest::UpdatePcrPolicy {
                    passphrase: Zeroizing::new("migration phrase".into()),
                    pcr_indices: vec![1],
                    credential_target: CredentialTarget::All { all: true },
                    default_policy_change: change,
                },
            );
            assert!(response.ok);
        }
        assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_passphrase_validation_preserves_default_even_with_no_targets() {
        let dir = std::env::temp_dir().join(format!("bad-passphrase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            dispatch(
                &dir,
                None,
                &ManagementRequest::SetupMigration {
                    passphrase: Zeroizing::new("setup phrase".into()),
                    pcr_indices: None,
                },
            )
            .ok
        );
        store::save_default_pcr_policy(&dir, &[1, 7]).unwrap();
        let tx = mock_worker(Err(ManagementError::Authentication));
        let response = dispatch(
            &dir,
            Some(&tx),
            &ManagementRequest::UpdatePcrPolicy {
                passphrase: Zeroizing::new("wrong phrase".into()),
                pcr_indices: vec![7],
                credential_target: CredentialTarget::All { all: true },
                default_policy_change: super::super::DefaultPcrPolicyChange::Disable,
            },
        );
        assert!(!response.ok);
        assert_eq!(
            store::load_default_pcr_policy(&dir).unwrap(),
            Some(vec![1, 7])
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enabling_requires_migration_but_existing_defaults_are_preserved_until_disabled() {
        let mut id = [0; 8];
        getrandom::fill(&mut id).unwrap();
        let dir = std::env::temp_dir().join(format!("pcr-config-{}", hex::encode(id)));
        let response = dispatch(
            &dir,
            None,
            &ManagementRequest::SetDefaultPcrPolicy {
                pcr_indices: vec![7],
            },
        );
        assert!(!response.ok);
        assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), None);
        // Older explicitly saved selections must still be shown, not silently
        // disabled just because no migration configuration exists yet.
        store::save_default_pcr_policy(&dir, &[1, 7]).unwrap();
        let shown = dispatch(&dir, None, &ManagementRequest::ShowConfig);
        assert!(shown.ok);
        assert_eq!(
            store::load_default_pcr_policy(&dir).unwrap(),
            Some(vec![1, 7])
        );
        assert!(dispatch(&dir, None, &ManagementRequest::DisableDefaultPcrPolicy).ok);
        assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
fn dispatch(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
) -> ManagementResponse {
    dispatch_until(
        store_dir,
        tx,
        request,
        Instant::now() + std::time::Duration::from_secs(30),
    )
}

pub(crate) fn dispatch_until(
    store_dir: &Path,
    tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
    deadline: Instant,
) -> ManagementResponse {
    match dispatch_result(store_dir, tx, request, deadline) {
        Ok(result) => ManagementResponse {
            ok: true,
            error: None,
            result: Some(result),
        },
        Err(error) => ManagementResponse {
            ok: false,
            error: Some(ManagementError::from_report(&error).to_string()),
            result: None,
        },
    }
}
