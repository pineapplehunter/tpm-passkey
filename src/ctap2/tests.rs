use super::*;
use p256::elliptic_curve::sec1::ToSec1Point;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn get_info_uses_project_aaguid_and_algorithm_metadata() {
    let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
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
        Some(&cbor!([2, 1]).expect("protocol list"))
    );
    assert!(map_value(&map, 2).is_none(), "no authenticator extensions");
}

#[test]
fn get_info_advertises_a_consistent_ctap21_configuration() {
    let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
        panic!("expected getInfo map");
    };

    let versions = map_value(&map, 1)
        .and_then(Value::as_array)
        .expect("versions");
    assert!(versions.contains(&cbor!("FIDO_2_0").expect("version")));
    assert!(versions.contains(&cbor!("FIDO_2_1").expect("version")));
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
    assert_eq!(map_bool(options, "uv"), None);
    assert_eq!(map_bool(options, "pinUvAuthToken"), Some(false));
    assert_eq!(map_bool(options, "credMgmt"), Some(true));
    assert_eq!(map_integer(&map, 13), Some(4));

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
fn pin_capabilities_follow_configuration_without_claiming_builtin_uv() {
    for configured in [false, true] {
        let response = get_info_response(configured);
        let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).unwrap() else {
            panic!("getInfo map")
        };
        let options = map_map(&map, 4).unwrap();
        assert_eq!(map_bool(options, "clientPin"), Some(configured));
        assert_eq!(map_bool(options, "pinUvAuthToken"), Some(configured));
        assert!(map_value(options, "uv").is_none());
    }
}

#[test]
fn approval_outcomes_use_command_specific_ctap_statuses() {
    struct Outcome(approval::ApprovalOutcome);
    impl approval::UserApproval for Outcome {
        fn approve(&self, _: &str) -> bool {
            panic!("controlled approval required")
        }
        fn approve_controlled(
            &self,
            _: &str,
            _: &approval::ApprovalControl,
        ) -> approval::ApprovalOutcome {
            self.0
        }
    }
    for outcome in [
        approval::ApprovalOutcome::Denied,
        approval::ApprovalOutcome::TimedOut,
        approval::ApprovalOutcome::Cancelled,
    ] {
        let mut auth = authenticator_with_credential("example.test", vec![1]);
        auth.approval = Box::new(Outcome(outcome));
        let status = match outcome {
            approval::ApprovalOutcome::TimedOut => ErrorStatus::UserActionTimeout,
            approval::ApprovalOutcome::Cancelled => ErrorStatus::KeepaliveCancel,
            _ => ErrorStatus::OperationDenied,
        };
        for command in [Ctap2Command::Selection, Ctap2Command::Reset] {
            assert_eq!(auth.handle_cbor(&[command.into()]), vec![u8::from(status)]);
        }
        let status = if outcome == approval::ApprovalOutcome::Cancelled {
            ErrorStatus::KeepaliveCancel
        } else {
            ErrorStatus::OperationDenied
        };
        for request in [
            ctap_request(
                Ctap2Command::MakeCredential,
                cbor!({
                    1 => bytes([0; 32]), 2 => {"id" => "example.test"},
                    3 => {"id" => bytes([1])}, 4 => [{"type" => "public-key", "alg" => -7}],
                })
                .unwrap(),
            ),
            ctap_request(
                Ctap2Command::MakeCredential,
                cbor!({
                    1 => bytes([0; 32]), 2 => {"id" => "example.test"},
                    3 => {"id" => bytes([1])}, 4 => [{"type" => "public-key", "alg" => -7}],
                    8 => bytes([]),
                })
                .unwrap(),
            ),
            ctap_request(
                Ctap2Command::GetAssertion,
                cbor!({
                    1 => "example.test", 2 => bytes([0; 32]),
                })
                .unwrap(),
            ),
        ] {
            assert_eq!(auth.handle_cbor(&request), vec![u8::from(status)]);
        }
        assert_eq!(auth.credentials.len(), 1);
        std::fs::remove_dir_all(auth.store_dir).unwrap();
    }
}

#[test]
fn client_only_and_unknown_extension_inputs_are_ignored() {
    let dir = test_store_dir("client-only-extensions");
    let count = Arc::new(AtomicUsize::new(0));
    let mut auth = Authenticator::new_with_approval(
        dir.clone(),
        None,
        Box::new(CountingApproval(count.clone())),
    );
    let request = ctap_request(
        Ctap2Command::MakeCredential,
        cbor!({
            1 => bytes([0; 32]), 2 => {"id" => "example.test"},
            3 => {"id" => bytes([1])}, 4 => [{"type" => "public-key", "alg" => -7}],
            6 => {"credProps" => "client-only", "unknown-extension" => {"arbitrary" => 7}},
        })
        .unwrap(),
    );
    assert_eq!(
        auth.handle_cbor(&request),
        vec![u8::from(ErrorStatus::OperationDenied)]
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "inputs passed validation and reached TPM setup"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn requesting_builtin_uv_never_falls_back_to_host_approval() {
    let dir = test_store_dir("unsupported-uv-options");
    let count = Arc::new(AtomicUsize::new(0));
    let mut auth = Authenticator::new_with_approval(
        dir.clone(),
        None,
        Box::new(CountingApproval(count.clone())),
    );
    for request in [
        ctap_request(
            Ctap2Command::MakeCredential,
            cbor!({
                1 => bytes([0; 32]), 2 => {"id" => "example.test"},
                3 => {"id" => bytes([1])}, 4 => [{"type" => "public-key", "alg" => -7}],
                7 => {"uv" => true},
            })
            .unwrap(),
        ),
        ctap_request(
            Ctap2Command::GetAssertion,
            cbor!({
                1 => "example.test", 2 => bytes([0; 32]), 5 => {"uv" => true},
            })
            .unwrap(),
        ),
    ] {
        assert_eq!(
            auth.handle_cbor(&request),
            vec![u8::from(ErrorStatus::InvalidOption)]
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn client_pin_rejects_known_wrong_types_and_out_of_range_integers() {
    let dir = test_store_dir("client-pin-field-types");
    let mut auth = Authenticator::new(dir.clone(), None);
    for key in [1, 3, 4, 5, 6, 9, 10] {
        let request = cbor!({2 => 1, key => false}).unwrap();
        assert_eq!(
            auth.handle_cbor(&ctap_request(Ctap2Command::ClientPin, request)),
            vec![u8::from(ErrorStatus::CborUnexpectedType)]
        );
    }
    for protocol in [-1, 0, 3, 256] {
        assert_eq!(
            auth.handle_cbor(&ctap_request(
                Ctap2Command::ClientPin,
                cbor!({1 => protocol, 2 => 2}).unwrap()
            )),
            vec![u8::from(ErrorStatus::InvalidParameter)]
        );
    }
    for permissions in [-1, 256] {
        assert_eq!(
            auth.handle_cbor(&ctap_request(
                Ctap2Command::ClientPin,
                cbor!({1 => 2, 2 => 9, 6 => bytes([0;32]), 9 => permissions}).unwrap()
            )),
            vec![u8::from(ErrorStatus::InvalidParameter)]
        );
    }
    let _ = std::fs::remove_dir_all(dir);
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
    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::GetInfo.into(), 0xa0]),
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
        Some(&cbor!({"test-extension" => true}).unwrap()),
    );

    assert_ne!(auth_data[32] & 0x80, 0);
}

#[test]
fn unsupported_and_unknown_commands_return_invalid_command() {
    let mut authenticator = Authenticator::default();
    for command in [0x09, 0x0c, 0x0d, 0x40, 0x41, 0xff] {
        assert_eq!(
            authenticator.handle_cbor(&[command]),
            error_response(ErrorStatus::InvalidCommand)
        );
    }
}

#[test]
fn selection_and_reset_have_no_parameters_or_response_map() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3]);
    authenticator.client_pin = Some(ClientPinState {
        pin_salt: vec![0; 32],
        pin_verifier: vec![0; 32],
        retries: PIN_RETRIES,
    });

    for command in [Ctap2Command::Selection, Ctap2Command::Reset] {
        assert_eq!(
            authenticator.handle_cbor(&ctap_request(
                command,
                cbor!({}).expect("unexpected parameters"),
            )),
            error_response(ErrorStatus::InvalidCbor)
        );
    }

    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::Selection.into()]),
        vec![0x00]
    );
    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::Reset.into()]),
        vec![0x00]
    );
    assert!(authenticator.credentials.is_empty());
    assert!(authenticator.client_pin.is_none());
    assert!(
        store::load_ctap2_credentials_from_dir(&authenticator.store_dir)
            .expect("load credentials after reset")
            .is_empty()
    );
}

#[test]
fn reset_is_only_allowed_during_the_power_up_window() {
    let approval_count = Arc::new(AtomicUsize::new(0));
    let store_dir = test_store_dir("late-reset");
    let mut authenticator = Authenticator::new_with_approval(
        store_dir.clone(),
        None,
        Box::new(CountingApproval(approval_count.clone())),
    );
    authenticator.powered_up_at = Instant::now() - Duration::from_secs(11);

    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::Reset.into()]),
        error_response(ErrorStatus::NotAllowed)
    );
    assert_eq!(approval_count.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(store_dir);
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
    let set_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({
            1 => 2,
            2 => 3,
            3 => client_key.clone(),
            4 => bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
            5 => bytes(encrypted_pin),
        })
        .expect("set-PIN request"),
    ));
    assert_eq!(set_response[0], 0x00);

    let retries = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 1 => 2, 2 => 1 }).expect("PIN-retries request"),
    ));
    let Value::Map(retries_map) = ciborium::from_reader::<Value, _>(&retries[1..]).expect("CBOR")
    else {
        panic!("expected getRetries response");
    };
    assert_eq!(map_integer(&retries_map, 3), Some(8));

    let pin_hash = Sha256::digest(b"1234");
    let encrypted_pin_hash = encrypt_aes(&aes_key, &pin_hash[..16]).expect("encrypt PIN hash");
    let token_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({
            1 => 2,
            2 => 9,
            3 => client_key,
            6 => bytes(encrypted_pin_hash),
            9 => 1,
            10 => "example.com",
        })
        .expect("PIN-token request"),
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
    let wrong_encrypted_hash = encrypt_aes(&aes_key, &wrong_hash[..16]).expect("encrypt PIN hash");
    let wrong_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({
            1 => 2,
            2 => 9,
            3 => client_key_agreement(&client_secret),
            6 => bytes(wrong_encrypted_hash),
            9 => 1,
            10 => "example.com",
        })
        .expect("wrong-PIN token request"),
    ));
    assert_eq!(wrong_response, vec![ErrorStatus::PinInvalid as u8]);

    for expected_status in [ErrorStatus::PinInvalid, ErrorStatus::PinAuthBlocked] {
        let retry_secret = EphemeralSecret::generate();
        let retry_server_key = client_pin_key_agreement(&mut authenticator);
        let retry_server_public =
            parse_key_agreement(&retry_server_key).expect("valid server public key");
        let (retry_aes_key, _) = derive_protocol2_keys(
            retry_secret
                .diffie_hellman(&retry_server_public)
                .raw_secret_bytes()
                .as_slice(),
        )
        .expect("derive protocol 2 keys");
        let wrong_encrypted_hash =
            encrypt_aes(&retry_aes_key, &wrong_hash[..16]).expect("encrypt PIN hash");
        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::ClientPin,
            cbor!({
                1 => 2,
                2 => 9,
                3 => client_key_agreement(&retry_secret),
                6 => bytes(wrong_encrypted_hash),
                9 => 1,
                10 => "example.com",
            })
            .expect("retry wrong-PIN request"),
        ));
        assert_eq!(response, vec![u8::from(expected_status)]);
    }

    let blocked_retries = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 2 => 1 }).expect("PIN-retries request"),
    ));
    let Value::Map(blocked_retries) =
        ciborium::from_reader::<Value, _>(&blocked_retries[1..]).expect("CBOR")
    else {
        panic!("expected blocked retries response");
    };
    assert_eq!(map_integer(&blocked_retries, 3), Some(5));
    assert_eq!(map_bool(&blocked_retries, 4), Some(true));

    let mut restored = Authenticator::new(store_dir.clone(), None);
    let restored_retries = restored.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 1 => 2, 2 => 1 }).expect("PIN-retries request"),
    ));
    let Value::Map(restored_map) =
        ciborium::from_reader::<Value, _>(&restored_retries[1..]).expect("CBOR")
    else {
        panic!("expected restored getRetries response");
    };
    assert_eq!(map_integer(&restored_map, 3), Some(5));

    let legacy_secret = EphemeralSecret::generate();
    let legacy_server_key = client_pin_key_agreement(&mut restored);
    let legacy_server_public =
        parse_key_agreement(&legacy_server_key).expect("valid server public key");
    let (legacy_aes_key, _) = derive_protocol2_keys(
        legacy_secret
            .diffie_hellman(&legacy_server_public)
            .raw_secret_bytes()
            .as_slice(),
    )
    .expect("derive protocol 2 keys");
    let encrypted_pin_hash =
        encrypt_aes(&legacy_aes_key, &pin_hash[..16]).expect("encrypt PIN hash");
    let legacy_response = restored.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({
            1 => 2,
            2 => 5,
            3 => client_key_agreement(&legacy_secret),
            6 => bytes(encrypted_pin_hash),
        })
        .expect("legacy token request"),
    ));
    assert_eq!(legacy_response[0], 0x00);
    let Value::Map(legacy_response) =
        ciborium::from_reader::<Value, _>(&legacy_response[1..]).expect("CBOR")
    else {
        panic!("expected legacy token response");
    };
    assert_eq!(legacy_response.len(), 1);
    assert_eq!(
        decrypt_aes(
            &legacy_aes_key,
            map_bytes(&legacy_response, 2).expect("encrypted legacy token")
        )
        .expect("decrypt legacy token")
        .len(),
        32
    );

    std::fs::remove_dir_all(store_dir).expect("remove test store");
}

#[test]
fn unsupported_builtin_uv_subcommands_do_not_mint_tokens() {
    let store_dir = test_store_dir("uv-token-unsupported");
    let approval_count = Arc::new(AtomicUsize::new(0));
    let mut authenticator = Authenticator::new_with_approval(
        store_dir.clone(),
        None,
        Box::new(CountingApproval(approval_count.clone())),
    );
    for subcommand in [6, 7] {
        for request in [
            cbor!({ 1 => 2, 2 => subcommand }).unwrap(),
            cbor!({ 2 => subcommand }).unwrap(),
        ] {
            assert_eq!(
                authenticator.handle_cbor(&ctap_request(Ctap2Command::ClientPin, request)),
                vec![u8::from(ErrorStatus::InvalidCommand)]
            );
        }
    }
    assert_eq!(approval_count.load(Ordering::SeqCst), 0);
    assert!(authenticator.pin_uv_auth_token.is_none());
    let _ = std::fs::remove_dir_all(store_dir);
}

#[test]
fn client_pin_wire_shape_and_permission_validation_follow_ctap22() {
    let store_dir = test_store_dir("client-pin-wire-shape");
    let mut authenticator = Authenticator::new(store_dir.clone(), None);

    let retries = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 2 => 1 }).expect("PIN-retries request"),
    ));
    assert_eq!(
        retries[0], 0x00,
        "getPINRetries does not require a protocol"
    );

    let unknown = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 2 => 8 }).expect("unknown ClientPIN request"),
    ));
    assert_eq!(unknown, vec![u8::from(ErrorStatus::InvalidSubcommand)]);

    let nested_parameters = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 1 => 2, 2 => 3, 4 => {} }).expect("nested ClientPIN request"),
    ));
    assert_eq!(
        nested_parameters,
        vec![u8::from(ErrorStatus::CborUnexpectedType)]
    );

    assert_eq!(
        validate_token_permissions(0, Some("example.com"), false),
        Err(ErrorStatus::InvalidParameter)
    );
    assert_eq!(
        validate_token_permissions(1, None, false),
        Err(ErrorStatus::MissingParameter)
    );
    assert_eq!(
        validate_token_permissions(8, None, false),
        Err(ErrorStatus::UnauthorizedPermission)
    );
    assert!(
        validate_token_permissions(0x80, None, false)
            .expect("undefined permission bits are ignored")
            .is_empty()
    );

    assert_eq!(
        validate_new_pin("éé".as_bytes()),
        Err(ErrorStatus::PinPolicyViolation)
    );
    assert_eq!(validate_new_pin("éééé".as_bytes()), Ok(()));

    let secret = EphemeralSecret::generate();
    let Value::Map(mut key) = client_key_agreement(&secret) else {
        panic!("expected key agreement map");
    };
    key.extend(cbor_map(
        cbor!({ 2 => bytes([1]) }).expect("extra key-agreement member"),
    ));
    assert!(matches!(
        parse_key_agreement(&key),
        Err(ErrorStatus::InvalidParameter)
    ));

    let token_value = vec![0x77; 32];
    let message = b"credential-management";
    let mut mac = HmacSha256::new_from_slice(&token_value).expect("HMAC key");
    mac.update(message);
    let auth_param = mac.finalize().into_bytes();
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: token_value,
        permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
        rp_id: None,
        issued_at: Instant::now() - Duration::from_secs(31),
        first_used_at: None,
        user_present_until: None,
    });
    assert_eq!(
        authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&auth_param),
            message,
            Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
            None,
        ),
        Err(ErrorStatus::PinAuthInvalid)
    );

    let _ = std::fs::remove_dir_all(store_dir);
}

#[test]
fn protocol2_authentication_parameters_are_full_length() {
    let key = [0x55; 32];
    let message = b"protocol-two-message";
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
    mac.update(message);
    let signature = mac.finalize().into_bytes();
    assert_eq!(verify_pin_uv_auth_param(&key, &signature, message), Ok(()));
    assert_eq!(
        verify_pin_uv_auth_param(&key, &signature[..16], message),
        Err(ErrorStatus::PinAuthInvalid)
    );
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
    // Exercise the browser flow from PIN setup through scoped token issuance
    // and makeCredential authentication. The pinUvAuthParam message for
    // makeCredential is exactly clientDataHash; RP scoping is checked against
    // the token separately.
    let store_dir = test_store_dir("make-credential-token-regression");
    let mut authenticator =
        Authenticator::new_with_approval(store_dir.clone(), None, Box::new(AlwaysApprove));

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
    let set_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({
            1 => 2,
            2 => 3,
            3 => client_key,
            4 => bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
            5 => bytes(encrypted_pin),
        })
        .expect("set-PIN request"),
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
        cbor!({
            1 => 2,
            2 => 9,
            3 => client_key2,
            6 => bytes(encrypted_pin_hash),
            9 => 1,
            10 => rp_id,
        })
        .expect("PIN-token request"),
    ));
    assert_eq!(token_response[0], 0x00, "getToken should succeed");
    let Value::Map(token_map) =
        ciborium::from_reader::<Value, _>(&token_response[1..]).expect("CBOR")
    else {
        panic!("expected token response map");
    };

    // ClientPIN token responses contain only key 2. Key 3 is pinRetries in
    // the response schema and strict browser decoders reject a byte string there.
    assert_eq!(token_map.len(), 1);
    let encrypted_token = map_bytes(&token_map, 2).expect("encrypted token (key 2)");
    let token = decrypt_aes(&aes_key2, encrypted_token).expect("decrypt token");
    assert_eq!(token.len(), 32, "pinUvAuthToken must be 32 bytes");

    let client_data_hash = [0xcc; 32];
    let mut mac = HmacSha256::new_from_slice(&token).expect("HMAC key");
    mac.update(&client_data_hash);
    let correct_auth_param = mac.finalize().into_bytes().to_vec();

    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &client_data_hash,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(result, Ok(true));

    // Exercise the public CTAP handler too. With no TPM test context, a valid
    // request reaches key creation and fails with OperationDenied rather than
    // being rejected as PinAuthInvalid.
    let make_credential_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::MakeCredential,
        cbor!({
            1 => bytes(client_data_hash),
            2 => { "id" => rp_id },
            3 => { "id" => bytes([0x42; 16]) },
            4 => [{ "type" => "public-key", "alg" => -7 }],
            8 => bytes(correct_auth_param.clone()),
            9 => 2,
        })
        .expect("make-credential request"),
    ));
    assert_eq!(
        make_credential_response[0],
        u8::from(ErrorStatus::OperationDenied)
    );

    // Appending rpId changes the HMAC message and must fail. Browsers send an
    // HMAC over clientDataHash only.
    let incorrect_message = [client_data_hash.as_slice(), rp_id.as_bytes()].concat();
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &incorrect_message,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(result, Err(ErrorStatus::PinAuthInvalid));

    // Re-inject token (was cleared by the previous error return)
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: token.clone(),
        permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
        rp_id: Some(rp_id.to_owned()),
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: None,
    });

    // Should be rejected: Some(rp_id) token with None rp_id passed
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &client_data_hash,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        None,
    );
    assert_eq!(
        result,
        Err(ErrorStatus::PinAuthInvalid),
        "REGRESSION 3: scoped token + None rp_id should be rejected"
    );

    // A legacy token without an RP ID is associated with the first mc/ga RP.
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: token.clone(),
        permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
        rp_id: None,
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: None,
    });
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &client_data_hash,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(result, Ok(true));
    assert_eq!(
        authenticator
            .pin_uv_auth_token
            .as_ref()
            .and_then(|token| token.rp_id.as_deref()),
        Some(rp_id)
    );
    assert_eq!(
        authenticator.validate_pin_uv_auth(
            Some(2),
            Some(&correct_auth_param),
            &client_data_hash,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some("other.example.com"),
        ),
        Err(ErrorStatus::PinAuthInvalid)
    );

    // ── getAssertion HMAC: clientDataHash only (CTAP 2.1 §6.2.1) ───────
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: token,
        permissions: Ctap2PermissionFlags::GET_ASSERTION,
        rp_id: Some(rp_id.to_owned()),
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: None,
    });
    let mut mac =
        HmacSha256::new_from_slice(&authenticator.pin_uv_auth_token.as_ref().unwrap().value)
            .expect("HMAC key");
    mac.update(&client_data_hash);
    let assertion_auth_param = mac.finalize().into_bytes().to_vec();
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
    let mut authenticator = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1, 2, 3], "example.com", 0),
            test_credential(vec![4, 5, 6], "example.com", 0),
        ],
    );
    let token = install_credential_management_token(&mut authenticator, None);

    let metadata = credential_management_request(&token, 1, None, true);
    let response = authenticator.handle_cbor(&metadata);
    let metadata = response_map(&response);
    assert_eq!(map_integer(&metadata, 1), Some(2));
    assert!(map_value(&metadata, 2).is_some());

    let params = cbor_map(
        cbor!({ 1 => bytes(Sha256::digest(b"example.com")) }).expect("credential parameters"),
    );
    let begin = credential_management_request(&token, 4, Some(params), true);
    let response = authenticator.handle_cbor(&begin);
    let first = response_map(&response);
    assert!(map_value(&first, 6).is_some(), "user uses response key 6");
    assert!(
        map_value(&first, 7).is_some(),
        "credential ID uses response key 7"
    );
    assert!(
        map_value(&first, 8).is_some(),
        "public key uses response key 8"
    );
    assert_eq!(map_integer(&first, 9), Some(2));

    let response =
        authenticator.handle_cbor(&credential_management_request(&token, 5, None, false));
    let next = response_map(&response);
    assert!(map_value(&next, 6).is_some());
    assert!(map_value(&next, 9).is_none());
    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(&token, 5, None, false)),
        error_response(ErrorStatus::NotAllowed)
    );
}

#[test]
fn credential_management_continuations_are_unauthenticated_but_strictly_stateful() {
    let mut authenticator = authenticator_with_credential("first.example", vec![1, 2, 3]);
    let mut second = authenticator.credentials[0].clone();
    second.id = vec![4, 5, 6];
    second.rp_id = "second.example".to_owned();
    authenticator.credentials.push(second);
    let token = install_credential_management_token(&mut authenticator, None);

    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(&token, 3, None, false)),
        error_response(ErrorStatus::NotAllowed)
    );

    let begin = authenticator.handle_cbor(&credential_management_request(&token, 2, None, true));
    let first = response_map(&begin);
    assert!(map_value(&first, 3).is_some(), "RP uses response key 3");
    assert!(
        map_value(&first, 4).is_some(),
        "RP hash uses response key 4"
    );
    assert_eq!(map_integer(&first, 5), Some(2));

    let next = authenticator.handle_cbor(&credential_management_request(&token, 3, None, false));
    let next = response_map(&next);
    assert!(map_value(&next, 3).is_some());
    assert!(map_value(&next, 5).is_none());

    // An unrelated operation interrupts the completed enumeration, and an
    // additional continuation fails with the stateful-command status.
    let metadata = credential_management_request(&token, 1, None, true);
    assert_eq!(authenticator.handle_cbor(&metadata)[0], 0x00);
    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(&token, 3, None, false)),
        error_response(ErrorStatus::NotAllowed)
    );
}

#[test]
fn credential_management_requires_authentication_and_valid_subcommands() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3]);
    let token = install_credential_management_token(&mut authenticator, None);

    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(&token, 1, None, false)),
        error_response(ErrorStatus::PuatRequired)
    );
    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(&token, 8, None, true)),
        error_response(ErrorStatus::InvalidSubcommand)
    );
}

#[test]
fn credential_management_update_preserves_user_handle_and_removes_empty_names() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3]);
    let token = install_credential_management_token(&mut authenticator, Some("example.com"));
    let descriptor = credential_descriptor(vec![1, 2, 3]);
    let wrong_params = cbor_map(
        cbor!({
            2 => descriptor.clone(),
            3 => { "id" => bytes([9, 9, 9]) },
        })
        .expect("update parameters"),
    );
    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(
            &token,
            7,
            Some(wrong_params),
            true,
        )),
        error_response(ErrorStatus::InvalidParameter)
    );

    let token = install_credential_management_token(&mut authenticator, Some("example.com"));
    let params = cbor_map(
        cbor!({
            2 => descriptor,
            3 => {
                "id" => bytes([5, 6, 7, 8]),
                "name" => "",
                "displayName" => "",
            },
        })
        .expect("update parameters"),
    );
    assert_eq!(
        authenticator.handle_cbor(&credential_management_request(
            &token,
            7,
            Some(params),
            true,
        ))[0],
        0x00
    );
    assert_eq!(authenticator.credentials[0].user_handle, vec![5, 6, 7, 8]);
    assert_eq!(authenticator.credentials[0].user_name, None);
    assert_eq!(authenticator.credentials[0].user_display_name, None);
}

#[test]
fn exclude_list_matches_only_credentials_for_the_requested_rp() {
    let authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);
    let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

    assert!(excluded_credential_exists(
        &authenticator.credentials,
        "example.com",
        Some(&exclude_list)
    ));
    assert!(!excluded_credential_exists(
        &authenticator.credentials,
        "other.example",
        Some(&exclude_list)
    ));
}

#[test]
fn allow_list_filter_accepts_absent_and_rejects_non_matching_descriptors() {
    assert!(allow_list_allows(None, &[1, 2, 3, 4]));
    assert!(!allow_list_allows(
        Some(&[credential_descriptor(vec![9, 9, 9, 9])]),
        &[1, 2, 3, 4]
    ));
}

#[test]
fn credential_descriptor_lists_require_nonempty_public_key_descriptors() {
    assert_eq!(
        validate_credential_descriptor_list(Some(&[]), true),
        Err(ErrorStatus::InvalidParameter)
    );
    assert_eq!(validate_credential_descriptor_list(None, true), Ok(()));

    let wrong_type = cbor!({
        "type" => "not-public-key",
        "id" => bytes([1, 2, 3, 4]),
    })
    .expect("wrong-type descriptor");
    let malformed = cbor!({ "type" => "public-key" }).expect("malformed descriptor");

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
fn make_credential_validates_every_algorithm_entry() {
    let valid = cbor!({ "type" => "public-key", "alg" => -7 }).expect("valid algorithm entry");
    let malformed = cbor!({ "type" => "public-key" }).expect("malformed algorithm entry");
    assert_eq!(
        validate_pub_key_cred_params(&[valid.clone(), malformed]),
        Err(ErrorStatus::InvalidCbor)
    );
    assert_eq!(
        validate_pub_key_cred_params(&[valid.clone(), valid]),
        Err(ErrorStatus::InvalidCbor)
    );
    assert_eq!(
        validate_pub_key_cred_params(&[
            cbor!({ "type" => "public-key", "alg" => -257 }).expect("unsupported algorithm entry"),
        ]),
        Err(ErrorStatus::UnsupportedAlgorithm)
    );
}

#[test]
fn zero_length_pin_uv_auth_uses_selection_statuses() {
    let store_dir = test_store_dir("zero-pin-uv-auth");
    let mut authenticator =
        Authenticator::new_with_approval(store_dir.clone(), None, Box::new(AlwaysApprove));
    let request = || {
        ctap_request(
            Ctap2Command::GetAssertion,
            cbor!({
                1 => "example.com",
                2 => bytes([0xaa; 32]),
                6 => bytes([]),
            })
            .expect("zero-length PIN/UV-auth request"),
        )
    };
    assert_eq!(
        authenticator.handle_cbor(&request()),
        vec![u8::from(ErrorStatus::PinNotSet)]
    );
    authenticator.client_pin = Some(ClientPinState {
        pin_salt: vec![0; 32],
        pin_verifier: vec![0; 32],
        retries: PIN_RETRIES,
    });
    assert_eq!(
        authenticator.handle_cbor(&request()),
        vec![u8::from(ErrorStatus::PinInvalid)]
    );
    let _ = std::fs::remove_dir_all(store_dir);
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
        validate_make_credential_options(Some(&options_text_map(&[("rk", "yes")]))),
        Err(ErrorStatus::InvalidCbor)
    );
    assert_eq!(
        validate_make_credential_options(Some(&options_map(&[("requireResidentKey", true)]))),
        Ok(())
    );
    assert_eq!(
        validate_make_credential_options(Some(&options_text_map(&[("residentKey", "required")]))),
        Ok(())
    );
    assert_eq!(
        validate_make_credential_options(Some(&options_text_map(&[("residentKey", "preferred")]))),
        Ok(())
    );
    // WebAuthn resident-key fields are not CTAP options and are ignored.
    assert_eq!(
        validate_make_credential_options(Some(&options_text_map(&[("residentKey", "surprise")]))),
        Ok(())
    );
    assert_eq!(
        validate_make_credential_options(Some(&options_map(&[("uv", true)]))),
        Ok(())
    );
    for options in [
        options_map(&[("up", false)]),
        options_map(&[("up", false), ("uv", true)]),
    ] {
        assert_eq!(
            validate_make_credential_options(Some(&options)),
            Err(ErrorStatus::InvalidOption)
        );
    }
}

#[test]
fn attestation_format_preferences_require_strings() {
    assert_eq!(validate_attestation_formats(None), Ok(()));
    assert_eq!(
        validate_attestation_formats(Some(&[cbor!("none").expect("format")])),
        Ok(())
    );
    assert_eq!(
        validate_attestation_formats(Some(&[cbor!(1).expect("invalid format")])),
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
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("up", false), ("uv", true)]))),
        Ok(())
    );
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("uv", true)]))),
        Ok(())
    );
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("rk", false)]))),
        Err(ErrorStatus::UnsupportedOption)
    );
}

#[test]
fn get_assertion_respects_the_requested_user_presence_flag() {
    for (requested, expected_flag) in [(true, 0x01), (false, 0x00)] {
        let mut authenticator =
            authenticator_with_credential("example.com", vec![u8::from(requested)]);
        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::GetAssertion,
            cbor!({
                1 => "example.com",
                2 => bytes([0xaa; 32]),
                5 => { "up" => requested },
            })
            .expect("assertion request"),
        ));
        assert_eq!(response[0], 0x00);
        let Value::Map(response) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
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
        cbor!({ 1 => "example.com", 2 => bytes([0xaa; 32]) }).expect("assertion request"),
    ));

    assert_eq!(response[0], 0x00);
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
        panic!("expected assertion map");
    };
    assert_eq!(map_integer(&map, 5), Some(2));

    let next = authenticator.handle_cbor(&[Ctap2Command::GetNextAssertion.into()]);
    assert_eq!(next[0], 0x00);
    let Value::Map(next_map) = ciborium::from_reader::<Value, _>(&next[1..]).expect("CBOR") else {
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
    assert_eq!(first_id, &[2]);
    assert_eq!(next_id, &[1]);
    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::GetNextAssertion.into()]),
        vec![u8::from(ErrorStatus::NotAllowed)]
    );
}

#[test]
fn allow_list_omits_user_count_and_next_assertion_state() {
    let mut authenticator = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1], "example.com", 1),
            test_credential(vec![2], "example.com", 2),
        ],
    );
    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({
            1 => "example.com",
            2 => bytes([0xaa; 32]),
            3 => [credential_descriptor(vec![1]), credential_descriptor(vec![2])],
            5 => { "up" => false },
        })
        .expect("allow-list assertion request"),
    ));
    assert_eq!(response[0], 0x00);
    let Value::Map(response) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
    else {
        panic!("expected assertion response");
    };
    assert!(map_value(&response, 4).is_none());
    assert!(map_value(&response, 5).is_none());
    assert_eq!(
        authenticator.handle_cbor(&[Ctap2Command::GetNextAssertion.into()]),
        vec![u8::from(ErrorStatus::NotAllowed)]
    );
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
        cbor!({ 1 => "example.com", 2 => bytes([0xaa; 32]) }).expect("assertion request"),
    ));
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
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
        cbor!({
            1 => bytes([0xaa; 32]),
            2 => { "id" => "example.com" },
            3 => { "id" => bytes([1]) },
            4 => [{ "type" => "public-key", "alg" => -7 }],
            5 => ["not-a-descriptor"],
            7 => { "up" => true },
        })
        .expect("malformed exclude-list request"),
    );
    assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

    let get_assertion = ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({
            1 => "example.com",
            2 => bytes([0xaa; 32]),
            3 => ["bad-entry"],
        })
        .expect("malformed allow-list request"),
    );
    assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
}

#[test]
fn empty_allow_list_is_invalid() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);

    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({
            1 => "example.com",
            2 => bytes([0xaa; 32]),
            3 => [],
        })
        .expect("empty allow-list request"),
    ));

    assert_eq!(response, vec![u8::from(ErrorStatus::InvalidParameter)]);
}

#[test]
fn client_data_hash_must_be_32_bytes() {
    let mut authenticator = Authenticator::default();

    let make_credential = ctap_request(
        Ctap2Command::MakeCredential,
        cbor!({
            1 => bytes([0xaa; 31]),
            2 => { "id" => "example.com" },
            3 => { "id" => bytes([1]) },
            4 => [{ "type" => "public-key", "alg" => -7 }],
        })
        .expect("short make-credential hash request"),
    );
    assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

    let get_assertion = ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({ 1 => "example.com", 2 => bytes([0xaa; 33]) }).expect("long assertion hash request"),
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
        cbor!({ 1 => "example.com", 2 => bytes([0xaa; 32]) }).expect("assertion request"),
    );
    let response = authenticator.handle_cbor(&get_assertion);
    assert_eq!(response[0], 0x27);
}

#[test]
fn assertion_enumeration_advances_only_after_counter_persistence() {
    let mut authenticator = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1], "example.com", 0),
            test_credential(vec![2], "example.com", 0),
            test_credential(vec![3], "example.com", 0),
        ],
    );
    let real_store = authenticator.store_dir.clone();
    let blocked_store = real_store.with_extension("blocked");
    std::fs::write(&blocked_store, b"not a directory").unwrap();
    let request = ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({ 1 => "example.com", 2 => bytes([0x11; 32]) }).unwrap(),
    );
    authenticator.store_dir = blocked_store.clone();
    assert_eq!(authenticator.handle_cbor(&request), vec![0x27]);
    assert!(authenticator.pending_assertion.is_none());
    authenticator.store_dir = real_store.clone();
    assert_eq!(authenticator.handle_cbor(&request)[0], 0);
    let indexes = authenticator
        .pending_assertion
        .as_ref()
        .unwrap()
        .credential_indexes
        .clone();
    authenticator.store_dir = blocked_store.clone();
    assert_eq!(
        authenticator.get_next_assertion(&[]),
        Err(ErrorStatus::OperationDenied)
    );
    assert_eq!(
        authenticator
            .pending_assertion
            .as_ref()
            .unwrap()
            .credential_indexes,
        indexes
    );
    assert_eq!(authenticator.credentials[indexes[0]].sign_count, 0);
    authenticator.store_dir = real_store.clone();
    assert!(authenticator.get_next_assertion(&[]).is_ok());
    assert_eq!(authenticator.credentials[indexes[0]].sign_count, 1);
    assert!(authenticator.get_next_assertion(&[]).is_ok());
    assert_eq!(
        authenticator.get_next_assertion(&[]),
        Err(ErrorStatus::NotAllowed)
    );
    std::fs::remove_file(blocked_store).unwrap();
    std::fs::remove_dir_all(real_store).unwrap();
}

#[test]
fn assertion_continuation_is_invalidated_by_expired_tokens_and_interruption() {
    let mut authenticator = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1], "example.com", 0),
            test_credential(vec![2], "example.com", 0),
        ],
    );
    let request = ctap_request(
        Ctap2Command::GetAssertion,
        cbor!({ 1 => "example.com", 2 => bytes([0x11; 32]) }).unwrap(),
    );
    assert_eq!(authenticator.handle_cbor(&request)[0], 0);
    let token = install_credential_management_token(&mut authenticator, None);
    authenticator.pending_assertion.as_mut().unwrap().token = Some(token);
    authenticator.pin_uv_auth_token.as_mut().unwrap().issued_at =
        Instant::now() - Duration::from_secs(601);
    assert_eq!(
        authenticator.get_next_assertion(&[]),
        Err(ErrorStatus::NotAllowed)
    );
    assert!(authenticator.pending_assertion.is_none());
    authenticator.pin_uv_auth_token = None;
    assert_eq!(authenticator.handle_cbor(&request)[0], 0);
    let interrupt = ctap_request(
        Ctap2Command::CredentialManagement,
        cbor!({ 1 => 99 }).unwrap(),
    );
    assert_eq!(authenticator.handle_cbor(&interrupt), vec![0x3e]);
    assert_eq!(
        authenticator.get_next_assertion(&[]),
        Err(ErrorStatus::NotAllowed)
    );
    std::fs::remove_dir_all(&authenticator.store_dir).unwrap();
}

#[test]
fn credential_metadata_update_rolls_back_when_storage_fails() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1]);
    let real_store = authenticator.store_dir.clone();
    let blocked_store = real_store.with_extension("blocked");
    std::fs::write(&blocked_store, b"not a directory").unwrap();
    authenticator.store_dir = blocked_store.clone();
    let old = authenticator.credentials[0].clone();
    let params = cbor_map(
        cbor!({
            2 => { "type" => "public-key", "id" => bytes(old.id.clone()) },
            3 => { "id" => bytes(old.user_handle.clone()), "name" => "replacement name" },
        })
        .unwrap(),
    );
    assert_eq!(
        authenticator.update_user_information(Some(&params)),
        Err(ErrorStatus::OperationDenied)
    );
    assert_eq!(authenticator.credentials[0], old);
    std::fs::remove_file(blocked_store).unwrap();
    std::fs::remove_dir_all(real_store).unwrap();
}

#[test]
fn pcr_binding_is_explicit_requires_recovery_and_never_retrofits_credentials() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1]);
    let dir = authenticator.store_dir.clone();
    let mut existing = store::load_ctap2_credentials_from_dir(&dir).unwrap();
    // A pre-existing bound credential may lack recovery. Keep it unchanged;
    // only new bound enrollment must satisfy the new recovery requirement.
    existing[0].policy = Some(store::StoredPcrPolicy {
        selection: "sha256:7".into(),
        digest: vec![1; 32],
        policy_ref: None,
        authority_name: None,
        authority_signature: None,
        policy_version: 1,
    });
    store::save_ctap2_credentials_to_dir(&dir, &existing).unwrap();
    assert!(authenticator.pcr_enrollment().unwrap().is_none());
    store::save_default_pcr_policy(&dir, &[7]).unwrap();
    assert!(matches!(
        authenticator.pcr_enrollment(),
        Err(ErrorStatus::OperationDenied)
    ));
    assert_eq!(store::load_default_pcr_policy(&dir).unwrap(), Some(vec![7]));
    store::clear_default_pcr_policy(&dir).unwrap();
    authenticator
        .set_recovery_passphrase(None, "optional PCR test phrase")
        .unwrap();
    assert!(
        authenticator.pcr_enrollment().unwrap().is_none(),
        "a phrase alone must not bind new keys"
    );
    store::save_default_pcr_policy(&dir, &[1, 7]).unwrap();
    assert_eq!(
        authenticator.pcr_enrollment().unwrap().unwrap().0,
        vec![1, 7]
    );
    let restarted = Authenticator::new_with_approval(dir.clone(), None, Box::new(AlwaysApprove));
    assert_eq!(
        store::load_default_pcr_policy(&dir).unwrap(),
        Some(vec![1, 7])
    );
    assert!(matches!(
        restarted.pcr_enrollment(),
        Err(ErrorStatus::OperationDenied)
    ));
    store::clear_default_pcr_policy(&dir).unwrap();
    assert!(
        restarted.pcr_enrollment().unwrap().is_none(),
        "unbound enrollment must not need recovery unlock"
    );
    let unchanged = store::load_ctap2_credentials_from_dir(&dir).unwrap();
    assert_eq!(unchanged[0].policy, existing[0].policy);
    assert_eq!(unchanged[0].key, existing[0].key);
    assert!(unchanged[0].recovery.is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn recovery_unlock_rotation_and_policy_updates_require_the_phrase() {
    let mut authenticator = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1], "example.com", 0),
            test_credential(vec![2], "example.com", 0),
        ],
    );
    authenticator
        .set_recovery_passphrase(None, "first recovery phrase")
        .unwrap();
    let unlocked = authenticator.recovery_unlock.as_ref().unwrap();
    let mut stored = store::load_ctap2_credentials_from_dir(&authenticator.store_dir).unwrap();
    for credential in &mut stored {
        let aad = recovery::credential_aad(&credential.id, &credential.key.public, b"policy-ref");
        credential.recovery = Some(store::StoredRecoverySlot {
            label: None,
            last_used: None,
            used_count: 0,
            key: credential.key.clone(),
            encrypted_auth: unlocked.encrypt(&[credential.id[0]; 32], &aad).unwrap(),
        });
        credential.policy = Some(store::StoredPcrPolicy {
            selection: "sha256:7".to_owned(),
            digest: vec![0; 32],
            policy_ref: Some(b"policy-ref".to_vec()),
            authority_name: Some(vec![1]),
            authority_signature: Some(vec![2]),
            policy_version: 1,
        });
    }
    store::save_ctap2_credentials_to_dir(&authenticator.store_dir, &stored).unwrap();
    let first_config = store::load_recovery_config(&authenticator.store_dir).unwrap();
    assert!(
        authenticator
            .set_recovery_passphrase(Some("wrong"), "second recovery phrase")
            .is_err()
    );
    assert_eq!(
        store::load_recovery_config(&authenticator.store_dir).unwrap(),
        first_config
    );
    authenticator
        .handle_tpm_command(TpmCommand::SetRecoveryPassphrase {
            old_passphrase: Some(Zeroizing::new("first recovery phrase".into())),
            new_passphrase: Zeroizing::new("second recovery phrase".into()),
        })
        .unwrap();
    for credential in store::load_ctap2_credentials_from_dir(&authenticator.store_dir).unwrap() {
        let slot = credential.recovery.as_ref().unwrap();
        assert_eq!(slot.used_count, 0);
        assert_eq!(slot.last_used, None);
        assert!(
            slot.unlock(&credential.id, b"policy-ref", "first recovery phrase")
                .is_err()
        );
        assert_eq!(
            slot.unlock(&credential.id, b"policy-ref", "second recovery phrase")
                .unwrap()
                .auth_value
                .unwrap()
                .as_slice(),
            [credential.id[0]; 32]
        );
    }
    // A later registration save cannot restore old encrypted slots from memory.
    authenticator.save_credentials().expect("save credentials");
    let config = store::load_recovery_config(&authenticator.store_dir)
        .unwrap()
        .unwrap();
    assert!(UnlockedRecovery::unlock(&config, "second recovery phrase").is_ok());
    let mut restarted = Authenticator::new_with_approval(
        authenticator.store_dir.clone(),
        None,
        Box::new(AlwaysApprove),
    );
    assert!(restarted.recovery_unlock.is_none());
    assert!(
        restarted
            .handle_tpm_command(TpmCommand::UnlockRecovery {
                passphrase: Zeroizing::new("wrong".into()),
            })
            .is_err()
    );
    assert!(restarted.recovery_unlock.is_none());
    restarted
        .handle_tpm_command(TpmCommand::UnlockRecovery {
            passphrase: Zeroizing::new("second recovery phrase".into()),
        })
        .unwrap();
    // Even with enrollment unlocked, policy updates must authenticate their own
    // request phrase before touching a TPM.
    let error = restarted
        .handle_tpm_command(TpmCommand::PcrPolicyUpdate(PcrPolicyUpdateCommand {
            credential_id: vec![1],
            pcr_indices: vec![7],
            passphrase: Zeroizing::new("wrong".into()),
        }))
        .unwrap_err();
    assert!(error.to_string().contains("incorrect recovery passphrase"));
    assert!(restarted.tpm.is_none());
    let stored = store::load_ctap2_credentials_from_dir(&authenticator.store_dir).unwrap();
    assert!(stored.iter().all(|credential| {
        let slot = credential.recovery.as_ref().unwrap();
        slot.used_count == 0 && slot.last_used.is_none()
    }));
    assert!(
        restarted
            .handle_tpm_command(TpmCommand::UnlockRecovery {
                passphrase: Zeroizing::new("wrong".into()),
            })
            .is_err()
    );
    assert!(restarted.recovery_unlock.is_none());
    std::fs::remove_dir_all(&authenticator.store_dir).unwrap();
}

#[test]
fn single_user_authenticator_reloads_the_shared_namespace() {
    let original = authenticator_with_credentials(
        "example.com",
        vec![
            test_credential(vec![1], "example.com", 0),
            test_credential(vec![2], "example.com", 0),
            test_credential(vec![3], "example.com", 0),
        ],
    );
    let credentials =
        store::load_ctap2_credentials_from_dir(&original.store_dir).expect("load credentials");

    let authenticator =
        Authenticator::new_with_approval(original.store_dir.clone(), None, Box::new(AlwaysApprove));
    assert_eq!(authenticator.credentials.len(), 3);
    for (loaded, stored) in authenticator.credentials.iter().zip(&credentials) {
        assert_eq!(loaded.id, stored.id);
    }
    let summaries = store::load_credential_summaries_from_dir(&original.store_dir)
        .expect("load all credential summaries");
    assert_eq!(summaries.len(), 3);
    std::fs::remove_dir_all(&original.store_dir).expect("remove test store");
}

struct AlwaysApprove;

struct CountingApproval(Arc<AtomicUsize>);

impl approval::UserApproval for CountingApproval {
    fn approve(&self, _prompt: &str) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}

impl approval::UserApproval for AlwaysApprove {
    fn approve(&self, _prompt: &str) -> bool {
        true
    }
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
            user_handle: credential.user_handle.clone(),
            user_name: credential.user_name.clone(),
            user_display_name: credential.user_display_name.clone(),
            key: store::StoredTpmKey {
                private: credential.key.private.clone(),
                public: credential.key.public.clone(),
                public_key_x: credential.key.public_key_x.clone(),
                public_key_y: credential.key.public_key_y.clone(),
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
        approval: Box::new(AlwaysApprove),
        recovery_unlock: None,
        credentials: credentials
            .into_iter()
            .map(|credential| Credential {
                id: credential.id,
                rp_id: rp_id.to_owned(),
                discoverable: true,
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
        client_pin_load_failed: false,
        key_agreement: None,
        pin_uv_auth_token: None,
        consecutive_pin_mismatches: 0,
        management: None,
        powered_up_at: Instant::now(),
        operation_cancelled: None,
        operation_status: None,
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
    ciborium::into_writer(&canonicalize_value(body), &mut payload).expect("serialize CTAP request");
    payload
}

fn test_store_dir(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tpm-passkey-ctap2-test-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn bytes(data: impl AsRef<[u8]>) -> Value {
    Value::Bytes(data.as_ref().to_vec())
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn cbor_map(value: Value) -> Vec<(Value, Value)> {
    let Value::Map(map) = value else {
        panic!("expected CBOR map");
    };
    map
}

fn credential_descriptor(id: Vec<u8>) -> Value {
    cbor!({
        "type" => "public-key",
        "id" => bytes(id),
    })
    .expect("credential descriptor")
}

fn client_pin_key_agreement(authenticator: &mut Authenticator) -> Vec<(Value, Value)> {
    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        cbor!({ 1 => 2, 2 => 2 }).expect("key-agreement request"),
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
    mac.finalize().into_bytes().to_vec()
}

#[test]
fn credential_management_authenticates_exact_canonical_parameter_bytes() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1]);
    let token = install_credential_management_token(&mut authenticator, None);
    let mut params = vec![0xa2, 1, 0x58, 32];
    params.extend_from_slice(&Sha256::digest(b"example.com"));
    // Unknown parameter 255 is ignored, but its valid 64-bit float encoding is
    // part of the authenticated message and MUST NOT be shortened to float16.
    params.extend_from_slice(&[0x18, 0xff, 0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
    let mut mac = HmacSha256::new_from_slice(&token).unwrap();
    mac.update(&[4]);
    mac.update(&params);
    let mut request = vec![0x0a, 0xa4, 1, 4, 2];
    request.extend_from_slice(&params);
    request.extend_from_slice(&[3, 2, 4, 0x58, 32]);
    request.extend_from_slice(&mac.finalize().into_bytes());
    assert_eq!(authenticator.handle_cbor(&request)[0], 0);
}

fn install_credential_management_token(
    authenticator: &mut Authenticator,
    rp_id: Option<&str>,
) -> Vec<u8> {
    let token = vec![0x33; 32];
    authenticator.client_pin = Some(ClientPinState {
        pin_salt: vec![0; 32],
        pin_verifier: vec![0; 32],
        retries: PIN_RETRIES,
    });
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: token.clone(),
        permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
        rp_id: rp_id.map(str::to_owned),
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: None,
    });
    token
}

fn credential_management_request(
    token: &[u8],
    sub_command: i128,
    params: Option<Vec<(Value, Value)>>,
    authenticated: bool,
) -> Vec<u8> {
    let auth_param = management_pin_auth(token, sub_command, params.as_deref());
    let request = match (params, authenticated) {
        (Some(params), true) => cbor!({
            1 => sub_command as i64,
            2 => map(params),
            3 => 2,
            4 => bytes(auth_param),
        }),
        (Some(params), false) => cbor!({
            1 => sub_command as i64,
            2 => map(params),
        }),
        (None, true) => cbor!({
            1 => sub_command as i64,
            3 => 2,
            4 => bytes(auth_param),
        }),
        (None, false) => cbor!({ 1 => sub_command as i64 }),
    }
    .expect("credential-management request");
    ctap_request(Ctap2Command::CredentialManagement, request)
}

fn response_map(response: &[u8]) -> Vec<(Value, Value)> {
    assert_eq!(
        response.first(),
        Some(&0x00),
        "unexpected response: {response:?}"
    );
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
        panic!("expected response map");
    };
    map
}

fn management_pin_auth(
    key: &[u8],
    sub_command: i128,
    params: Option<&[(Value, Value)]>,
) -> Vec<u8> {
    let message = management_auth_message(sub_command, params);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(&message);
    mac.finalize().into_bytes().to_vec()
}

fn options_map(options: &[(&str, bool)]) -> Vec<(Value, Value)> {
    options
        .iter()
        .map(|(key, value)| {
            (
                cbor!(*key).expect("option name"),
                cbor!(*value).expect("option value"),
            )
        })
        .collect()
}

fn options_text_map(options: &[(&str, &str)]) -> Vec<(Value, Value)> {
    options
        .iter()
        .map(|(key, value)| {
            (
                cbor!(*key).expect("option name"),
                cbor!(*value).expect("option value"),
            )
        })
        .collect()
}
