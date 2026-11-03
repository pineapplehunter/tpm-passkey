use super::*;

fn new_pin_authenticator() -> Authenticator {
    let mut id = [0; 8];
    getrandom::fill(&mut id).unwrap();
    let store = std::env::temp_dir().join(format!("ctap-pin-{}", hex::encode(id)));
    let mut authenticator = Authenticator::new(store, None);
    let correct = Sha256::digest(b"1234");
    let salt = vec![0x31; 32];
    authenticator.client_pin = Some(ClientPinState {
        pin_verifier: pin_verifier(&salt, &correct[..16]),
        pin_salt: salt,
        retries: PIN_RETRIES,
    });
    authenticator
}

#[test]
fn pin_load_failure_blocks_operations_until_repair_or_explicit_reset() {
    struct Consent(Arc<AtomicBool>);
    impl approval::UserApproval for Consent {
        fn approve(&self, _: &str) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    let auth = new_pin_authenticator();
    auth.persist_client_pin(auth.client_pin.as_ref().unwrap())
        .unwrap();
    let store = auth.store_dir.clone();
    let key_path = store.join("integrity.hmac-key");
    let key = std::fs::read(&key_path).unwrap();
    std::fs::write(&key_path, [0; 31]).unwrap();
    let consent = Arc::new(AtomicBool::new(false));
    let mut blocked =
        Authenticator::new_with_approval(store.clone(), None, Box::new(Consent(consent.clone())));
    assert!(blocked.client_pin_load_failed);
    blocked.cancel_pending();
    for command in [
        Ctap2Command::ClientPin,
        Ctap2Command::MakeCredential,
        Ctap2Command::GetAssertion,
        Ctap2Command::GetNextAssertion,
        Ctap2Command::CredentialManagement,
    ] {
        assert_eq!(
            blocked.handle_cbor(&[command.into()]),
            vec![u8::from(ErrorStatus::IntegrityFailure)]
        );
    }
    let info = blocked.handle_cbor(&[Ctap2Command::GetInfo.into()]);
    let info = decode_map(&info[1..]).unwrap();
    assert_eq!(
        map_bool(map_map(&info, 4).unwrap(), "clientPin"),
        Some(true)
    );
    assert_eq!(
        blocked.handle_cbor(&[Ctap2Command::Reset.into()]),
        vec![u8::from(ErrorStatus::OperationDenied)]
    );
    assert!(blocked.client_pin_load_failed);

    // Restoring the original file and restarting repairs without deleting PIN state.
    std::fs::write(&key_path, key).unwrap();
    let repaired = Authenticator::new(store.clone(), None);
    assert!(!repaired.client_pin_load_failed);
    assert!(repaired.client_pin.is_some());
    // The already-running failed instance remains blocked until successful reset.
    assert!(blocked.client_pin_load_failed);
    consent.store(true, Ordering::SeqCst);
    assert_eq!(blocked.handle_cbor(&[Ctap2Command::Reset.into()]), vec![0]);
    assert!(!blocked.client_pin_load_failed);
    assert!(
        store::load_client_pin_state_from_dir(&store)
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn pin_throttle_requires_a_power_cycle_even_for_the_correct_pin() {
    let mut authenticator = new_pin_authenticator();
    for expected in [
        ErrorStatus::PinInvalid,
        ErrorStatus::PinInvalid,
        ErrorStatus::PinAuthBlocked,
    ] {
        assert_eq!(authenticator.authenticate_pin(&[0; 16]), Err(expected));
    }
    let correct = Sha256::digest(b"1234");
    assert_eq!(
        authenticator.authenticate_pin(&correct[..16]),
        Err(ErrorStatus::PinAuthBlocked)
    );
    assert_eq!(
        authenticator.authenticate_pin(&[0; 16]),
        Err(ErrorStatus::PinAuthBlocked)
    );
    assert_eq!(authenticator.client_pin.as_ref().unwrap().retries, 5);
    let store = authenticator.store_dir.clone();
    let mut restarted = Authenticator::new(store.clone(), None);
    assert_eq!(restarted.authenticate_pin(&correct[..16]), Ok(()));
    assert_eq!(restarted.client_pin.as_ref().unwrap().retries, PIN_RETRIES);
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn pin_exhaustion_persists_across_power_cycles() {
    let mut authenticator = new_pin_authenticator();
    let store = authenticator.store_dir.clone();
    for remaining in (0..PIN_RETRIES).rev() {
        if authenticator.consecutive_pin_mismatches == 3 {
            authenticator = Authenticator::new(store.clone(), None);
        }
        let response = authenticator.authenticate_pin(&[0; 16]);
        assert_eq!(
            authenticator.client_pin.as_ref().unwrap().retries,
            remaining
        );
        assert_eq!(
            response,
            Err(if remaining == 0 {
                ErrorStatus::PinBlocked
            } else if authenticator.consecutive_pin_mismatches == 3 {
                ErrorStatus::PinAuthBlocked
            } else {
                ErrorStatus::PinInvalid
            })
        );
    }
    let mut restarted = Authenticator::new(store.clone(), None);
    let correct = Sha256::digest(b"1234");
    assert_eq!(
        restarted.authenticate_pin(&correct[..16]),
        Err(ErrorStatus::PinBlocked)
    );
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn retry_state_fails_closed_when_persistence_fails() {
    let mut authenticator = new_pin_authenticator();
    // A file in place of the directory makes the next store write fail.
    std::fs::write(&authenticator.store_dir, b"not a directory").unwrap();
    assert_eq!(
        authenticator.authenticate_pin(&[0; 16]),
        Err(ErrorStatus::OperationDenied)
    );
    assert_eq!(authenticator.client_pin.as_ref().unwrap().retries, 7);
    let correct = Sha256::digest(b"1234");
    assert_eq!(
        authenticator.authenticate_pin(&correct[..16]),
        Err(ErrorStatus::OperationDenied)
    );
    assert_eq!(authenticator.client_pin.as_ref().unwrap().retries, 7);
    std::fs::remove_file(authenticator.store_dir).unwrap();
}
