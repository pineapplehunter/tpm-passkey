use super::*;
use p256::elliptic_curve::sec1::ToSec1Point;

#[test]
fn get_info_starts_with_success() {
    let response = Authenticator::default().handle_cbor(&[Ctap2Command::GetInfo.into()]);
    assert_eq!(response[0], 0x00);
    assert!(response.len() > 1);
}

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
        Some(&Value::Array(vec![Value::Integer(2.into())]))
    );
    assert_eq!(
        map_value(&map, 2),
        Some(&Value::Array(vec![Value::Text("credProps".to_owned())]))
    );
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
    assert!(versions.contains(&Value::Text("FIDO_2_0".to_owned())));
    assert!(versions.contains(&Value::Text("FIDO_2_1".to_owned())));
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
    assert_eq!(map_bool(options, "uv"), Some(true));
    assert_eq!(map_bool(options, "pinUvAuthToken"), Some(true));
    assert_eq!(map_bool(options, "credMgmt"), Some(true));

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
        Some(&cred_props_extension(true)),
    );

    assert_ne!(auth_data[32] & 0x80, 0);
}

#[test]
fn unknown_command_is_rejected() {
    assert_eq!(
        Authenticator::default().handle_cbor(&[0xff]),
        error_response(ErrorStatus::InvalidCommand)
    );
}

#[test]
fn unsupported_commands_do_not_panic() {
    let mut authenticator = Authenticator::default();
    for command in [0x09, 0x0c, 0x0d, 0x40] {
        assert_eq!(
            authenticator.handle_cbor(&[command]),
            error_response(ErrorStatus::InvalidCommand)
        );
    }
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
    let set_params = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Bytes(encrypted_pin.clone()),
        ),
        (
            Value::Integer(2.into()),
            Value::Bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
        ),
    ]);
    let set_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(3.into())),
            (Value::Integer(3.into()), client_key.clone()),
            (Value::Integer(4.into()), set_params),
        ]),
    ));
    assert_eq!(set_response[0], 0x00);

    let retries = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(1.into())),
        ]),
    ));
    let Value::Map(retries_map) = ciborium::from_reader::<Value, _>(&retries[1..]).expect("CBOR")
    else {
        panic!("expected getRetries response");
    };
    assert_eq!(map_value(&retries_map, 3), Some(&Value::Integer(8.into())));

    let pin_hash = Sha256::digest(b"1234");
    let encrypted_pin_hash = encrypt_aes(&aes_key, &pin_hash[..16]).expect("encrypt PIN hash");
    let token_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(9.into())),
            (Value::Integer(3.into()), client_key),
            (Value::Integer(6.into()), Value::Bytes(encrypted_pin_hash)),
            (Value::Integer(9.into()), Value::Integer(1.into())),
        ]),
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
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(9.into())),
            (
                Value::Integer(3.into()),
                client_key_agreement(&client_secret),
            ),
            (Value::Integer(6.into()), Value::Bytes(wrong_encrypted_hash)),
            (Value::Integer(9.into()), Value::Integer(1.into())),
        ]),
    ));
    assert_eq!(wrong_response, vec![ErrorStatus::PinInvalid as u8]);

    let mut restored = Authenticator::new(store_dir.clone(), None);
    let restored_retries = restored.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(1.into())),
        ]),
    ));
    let Value::Map(restored_map) =
        ciborium::from_reader::<Value, _>(&restored_retries[1..]).expect("CBOR")
    else {
        panic!("expected restored getRetries response");
    };
    assert_eq!(map_value(&restored_map, 3), Some(&Value::Integer(7.into())));
    std::fs::remove_dir_all(store_dir).expect("remove test store");
}

#[test]
fn protocol2_uv_token_uses_subcommand_6_without_a_pin_hash() {
    let store_dir = test_store_dir("uv-token");
    let mut authenticator =
        Authenticator::new_with_approval(store_dir.clone(), None, Box::new(AlwaysApprove));
    let client_secret = EphemeralSecret::generate();
    let server_key = client_pin_key_agreement(&mut authenticator);
    let server_public = parse_key_agreement(&server_key).expect("valid server public key");
    let (aes_key, _) = derive_protocol2_keys(
        client_secret
            .diffie_hellman(&server_public)
            .raw_secret_bytes()
            .as_slice(),
    )
    .expect("derive protocol 2 keys");

    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(6.into())),
            (
                Value::Integer(3.into()),
                client_key_agreement(&client_secret),
            ),
            (Value::Integer(9.into()), Value::Integer(1.into())),
            (
                Value::Integer(10.into()),
                Value::Text("passkeys.io".to_owned()),
            ),
        ]),
    ));
    assert_eq!(response[0], 0x00);
    let Value::Map(response) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR")
    else {
        panic!("expected UV token response");
    };
    let encrypted_token = map_bytes(&response, 2).expect("encrypted token");
    assert_eq!(
        decrypt_aes(&aes_key, encrypted_token)
            .expect("decrypt token")
            .len(),
        32
    );
    assert_eq!(map_bytes(&response, 3).map(<[u8]>::len), Some(32));

    let retries = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(7.into())),
        ]),
    ));
    let Value::Map(retries) = ciborium::from_reader::<Value, _>(&retries[1..]).expect("CBOR")
    else {
        panic!("expected UV retries response");
    };
    assert_eq!(
        map_value(&retries, 5),
        Some(&Value::Integer(UV_RETRIES.into()))
    );
    let _ = std::fs::remove_dir_all(store_dir);
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
    // Regression test for three related CTAP 2.1 PinUvAuthProtocol 2 bugs in the
    // pinUvAuthToken flow that broke browser (Chrome/Firefox) makeCredential and
    // getAssertion operations after a ClientPIN token exchange.
    //
    // Bug 1 — Missing key 3 in getPinUvAuthToken response (src/ctap2.rs ~1109):
    //   CTAP 2.1 Protocol 2 requires pinUvAuthParam (key 3) in the token response:
    //   HMAC-SHA256(hmac_key, encrypted_token)[0..16]. Before the fix, only key 2
    //   (encrypted token) was returned, which broke browser integrity verification.
    //
    // Bug 2 — Wrong HMAC message for makeCredential (src/ctap2.rs ~329):
    //   CTAP 2.1 §6.1.1 defines the pinUvAuthParam HMAC message for makeCredential as
    //   `clientDataHash || rpId`, not just `clientDataHash`. The old code only passed
    //   `client_data_hash`, so the HMAC never matched what the browser computed.
    //
    // Bug 3 — rp_id=None in makeCredential token check (src/ctap2.rs ~331):
    //   validate_pin_uv_auth compares the token's rp_id against the passed rp_id via
    //   `is_some_and(|token_rp_id| Some(token_rp_id) != rp_id)`. When rp_id=None,
    //   `Some(token_rp_id) != None` is always true, so every token with a scoped rp_id
    //   was rejected, even for the correct RP.
    let store_dir = test_store_dir("make-credential-token-regression");
    let mut authenticator = Authenticator::new(store_dir.clone(), None);

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
    let set_params = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Bytes(encrypted_pin.clone()),
        ),
        (
            Value::Integer(2.into()),
            Value::Bytes(pin_auth_param(&hmac_key, &encrypted_pin)),
        ),
    ]);
    let set_response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(3.into())),
            (Value::Integer(3.into()), client_key),
            (Value::Integer(4.into()), set_params),
        ]),
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
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(9.into())),
            (Value::Integer(3.into()), client_key2),
            (Value::Integer(6.into()), Value::Bytes(encrypted_pin_hash)),
            (Value::Integer(9.into()), Value::Integer(1.into())),
            (Value::Integer(10.into()), Value::Text(rp_id.to_owned())),
        ]),
    ));
    assert_eq!(token_response[0], 0x00, "getToken should succeed");
    let Value::Map(token_map) =
        ciborium::from_reader::<Value, _>(&token_response[1..]).expect("CBOR")
    else {
        panic!("expected token response map");
    };

    // Decrypt the token from key 2 for HMAC computations
    let encrypted_token = map_bytes(&token_map, 2).expect("encrypted token (key 2)");
    let token = decrypt_aes(&aes_key2, encrypted_token).expect("decrypt token");
    assert_eq!(token.len(), 32, "pinUvAuthToken must be 32 bytes");

    // key 3 (pinUvAuthParam) MUST equal HMAC-SHA256(token,
    // encryptedToken) over the full 32-byte digest (PIN/UV Auth
    // Protocol 2). This is exactly what libfido2 / browsers verify,
    // so a mismatch here is what makes a browser reject the token
    // and close the device.
    let expected_pin_uv_auth_param = {
        let mut mac = HmacSha256::new_from_slice(&token).expect("HMAC key");
        mac.update(encrypted_token);
        mac.finalize().into_bytes().to_vec()
    };
    let pin_uv_auth_param = map_bytes(&token_map, 3).expect("pinUvAuthParam (key 3)");
    assert_eq!(
        pin_uv_auth_param,
        expected_pin_uv_auth_param.as_slice(),
        "key 3 must be HMAC-SHA256(token, encryptedToken)"
    );

    // ── REGRESSION 2+3: validate_pin_uv_auth for makeCredential ─────────
    let client_data_hash = [0xcc; 32];

    // CTAP 2.1 §6.1.1: makeCredential message = clientDataHash || rpId
    let make_cred_message = [client_data_hash.as_slice(), rp_id.as_bytes()].concat();
    let mut mac = HmacSha256::new_from_slice(&token).expect("HMAC key");
    mac.update(&make_cred_message);
    // PIN/UV Auth Protocol 2 returns the full 32-byte HMAC (libfido2
    // cbor_encode_pin_auth: outlen = dgst_len for protocol 2).
    let correct_auth_param = mac.finalize().into_bytes().to_vec();

    // Should succeed: correct HMAC message + Some(rp_id)
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &make_cred_message,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(
        result,
        Ok(true),
        "REGRESSION 2+3: clientDataHash||rpId + Some(rp_id) should pass"
    );

    // Simulate the old buggy server behavior: browser sends HMAC over
    // clientDataHash || rpId (CTAP 2.1 §6.1.1), but the server (before the
    // fix) only verified HMAC over clientDataHash. Since the HMAC messages
    // differ, the comparison should fail.
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param), // browser's HMAC = HMAC(token, clientDataHash || rpId)
        &client_data_hash,         // OLD server message = clientDataHash only (BUG)
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(
        result,
        Err(ErrorStatus::PinAuthInvalid),
        "REGRESSION 2: old server message (clientDataHash) vs browser's (clientDataHash||rpId)"
    );

    // Re-inject token (was cleared by the previous error return)
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        value: token.clone(),
        permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
        rp_id: Some(rp_id.to_owned()),
        issued_at: Instant::now(),
    });

    // Should be rejected: Some(rp_id) token with None rp_id passed
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &make_cred_message,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        None,
    );
    assert_eq!(
        result,
        Err(ErrorStatus::PinAuthInvalid),
        "REGRESSION 3: scoped token + None rp_id should be rejected"
    );

    // Token without rp_id should work for any rp_id
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        value: token.clone(),
        permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
        rp_id: None,
        issued_at: Instant::now(),
    });
    let result = authenticator.validate_pin_uv_auth(
        Some(2),
        Some(&correct_auth_param),
        &make_cred_message,
        Ctap2PermissionFlags::MAKE_CREDENTIAL,
        Some(rp_id),
    );
    assert_eq!(
        result,
        Ok(true),
        "token without rp_id should be valid for any rp_id"
    );

    // ── getAssertion HMAC: clientDataHash only (CTAP 2.1 §6.2.1) ───────
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        value: token,
        permissions: Ctap2PermissionFlags::GET_ASSERTION,
        rp_id: Some(rp_id.to_owned()),
        issued_at: Instant::now(),
    });
    let mut mac =
        HmacSha256::new_from_slice(&authenticator.pin_uv_auth_token.as_ref().unwrap().value)
            .expect("HMAC key");
    mac.update(&client_data_hash);
    let assertion_auth_param = mac.finalize().into_bytes()[..16].to_vec();
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
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3]);
    let token = vec![0x33; 32];
    authenticator.client_pin = Some(ClientPinState {
        pin_salt: vec![0; 32],
        pin_verifier: vec![0; 32],
        retries: PIN_RETRIES,
    });
    authenticator.pin_uv_auth_token = Some(PinUvAuthToken {
        value: token.clone(),
        permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
        rp_id: None,
        issued_at: Instant::now(),
    });

    let request = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer(3.into()), Value::Integer(2.into())),
        (
            Value::Integer(4.into()),
            Value::Bytes(management_pin_auth(&token, 1, None)),
        ),
    ]);
    let response =
        authenticator.handle_cbor(&ctap_request(Ctap2Command::CredentialManagement, request));
    assert_eq!(response[0], 0x00);
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
        panic!("expected credential-management response");
    };
    assert_eq!(map_value(&map, 1), Some(&Value::Integer(1.into())));
}

#[test]
fn exclude_list_detects_existing_credential_for_same_rp() {
    let authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);
    let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

    assert!(excluded_credential_exists(
        &authenticator.credentials,
        "example.com",
        Some(&exclude_list)
    ));
}

#[test]
fn exclude_list_ignores_matching_id_for_different_rp() {
    let authenticator = authenticator_with_credential("other.example", vec![1, 2, 3, 4]);
    let exclude_list = vec![credential_descriptor(vec![1, 2, 3, 4])];

    assert!(!excluded_credential_exists(
        &authenticator.credentials,
        "example.com",
        Some(&exclude_list)
    ));
}

#[test]
fn allow_list_absent_allows_any_credential() {
    assert!(allow_list_allows(None, &[1, 2, 3, 4]));
}

#[test]
fn allow_list_absent_or_empty_allows_any_credential() {
    assert!(allow_list_allows(Some(&[]), &[1, 2, 3, 4]));
    assert!(allow_list_allows(None, &[1, 2, 3, 4]));
}

#[test]
fn allow_list_non_matching_rejects_credential() {
    assert!(!allow_list_allows(
        Some(&[credential_descriptor(vec![9, 9, 9, 9])]),
        &[1, 2, 3, 4]
    ));
}

#[test]
fn credential_descriptor_requires_public_key_type_and_matching_id() {
    let wrong_type = Value::Map(vec![
        (
            Value::Text("type".to_owned()),
            Value::Text("not-public-key".to_owned()),
        ),
        (Value::Text("id".to_owned()), Value::Bytes(vec![1, 2, 3, 4])),
    ]);
    let malformed = Value::Map(vec![(
        Value::Text("type".to_owned()),
        Value::Text("public-key".to_owned()),
    )]);

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
    assert_eq!(
        validate_make_credential_options(Some(&options_text_map(&[("residentKey", "surprise")]))),
        Err(ErrorStatus::InvalidCbor)
    );
}

#[test]
fn attestation_conveyance_accepts_common_browser_values() {
    assert_eq!(validate_attestation_conveyance(None), Ok(()));
    assert_eq!(validate_attestation_conveyance(Some("none")), Ok(()));
    assert_eq!(validate_attestation_conveyance(Some("indirect")), Ok(()));
    assert_eq!(validate_attestation_conveyance(Some("direct")), Ok(()));
    assert_eq!(validate_attestation_conveyance(Some("enterprise")), Ok(()));
    assert_eq!(
        validate_attestation_conveyance(Some("unexpected")),
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
}

#[test]
fn options_reject_required_user_verification() {
    assert_eq!(
        validate_make_credential_options(Some(&options_map(&[("uv", true)]))),
        Ok(())
    );
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("uv", true)]))),
        Ok(())
    );
}

#[test]
fn options_accept_disabled_user_presence_with_uv() {
    // Some sites (e.g. github.com) send up=false alongside uv=true on
    // makeCredential; this combination must also be accepted.
    assert_eq!(
        validate_make_credential_options(Some(&options_map(&[("up", false), ("uv", true)]))),
        Ok(())
    );
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("up", false), ("uv", true)]))),
        Ok(())
    );
}

#[test]
fn options_accept_disabled_user_presence_without_uv() {
    // Regression: webauthn.io sends authenticatorMakeCredential and
    // authenticatorGetAssertion with up=false but no uv=true.  Both
    // were rejected as UnsupportedOption.
    assert_eq!(
        validate_make_credential_options(Some(&options_map(&[("up", false)]))),
        Ok(())
    );
    assert_eq!(
        validate_get_assertion_options(Some(&options_map(&[("up", false)]))),
        Ok(())
    );
}

#[test]
fn get_assertion_respects_the_requested_user_presence_flag() {
    for (requested, expected_flag) in [(true, 0x01), (false, 0x00)] {
        let mut authenticator =
            authenticator_with_credential("example.com", vec![u8::from(requested)]);
        let response = authenticator.handle_cbor(&ctap_request(
            Ctap2Command::GetAssertion,
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("example.com".to_owned()),
                ),
                (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
                (
                    Value::Integer(5.into()),
                    Value::Map(options_map(&[("up", requested)])),
                ),
            ]),
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
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
        ]),
    ));

    assert_eq!(response[0], 0x00);
    let Value::Map(map) = ciborium::from_reader::<Value, _>(&response[1..]).expect("CBOR") else {
        panic!("expected assertion map");
    };
    assert_eq!(map_value(&map, 5), Some(&Value::Integer(2.into())));

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
    assert_ne!(first_id, next_id);
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
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
        ]),
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
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 32])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(
                    Value::Text("id".to_owned()),
                    Value::Text("example.com".to_owned()),
                )]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("type".to_owned()),
                        Value::Text("public-key".to_owned()),
                    ),
                    (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                ])]),
            ),
            (
                Value::Integer(5.into()),
                Value::Array(vec![Value::Text("not-a-descriptor".to_owned())]),
            ),
            (
                Value::Integer(7.into()),
                Value::Map(vec![(Value::Text("up".to_owned()), Value::Bool(true))]),
            ),
        ]),
    );
    assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

    let get_assertion = ctap_request(
        Ctap2Command::GetAssertion,
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Text("bad-entry".to_owned())]),
            ),
        ]),
    );
    assert_eq!(authenticator.handle_cbor(&get_assertion)[0], 0x12);
}

#[test]
fn empty_allow_list_matches_discoverable_credentials() {
    let mut authenticator = authenticator_with_credential("example.com", vec![1, 2, 3, 4]);

    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::GetAssertion,
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
            (Value::Integer(3.into()), Value::Array(Vec::new())),
        ]),
    ));

    assert_eq!(response[0], 0x00);
}

#[test]
fn client_data_hash_must_be_32_bytes() {
    let mut authenticator = Authenticator::default();

    let make_credential = ctap_request(
        Ctap2Command::MakeCredential,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0xaa; 31])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(
                    Value::Text("id".to_owned()),
                    Value::Text("example.com".to_owned()),
                )]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(Value::Text("id".to_owned()), Value::Bytes(vec![1]))]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("type".to_owned()),
                        Value::Text("public-key".to_owned()),
                    ),
                    (Value::Text("alg".to_owned()), Value::Integer((-7).into())),
                ])]),
            ),
        ]),
    );
    assert_eq!(authenticator.handle_cbor(&make_credential)[0], 0x12);

    let get_assertion = ctap_request(
        Ctap2Command::GetAssertion,
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 33])),
        ]),
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
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Text("example.com".to_owned()),
            ),
            (Value::Integer(2.into()), Value::Bytes(vec![0xaa; 32])),
        ]),
    );
    let response = authenticator.handle_cbor(&get_assertion);
    assert_eq!(response[0], 0x27);
}

struct AlwaysApprove;

impl approval::UserApproval for AlwaysApprove {
    fn approve(&self, _prompt: &str, _session: &session::SessionContext) -> bool {
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
            user_id: Some(1000),
            user_handle: credential.user_handle.clone(),
            user_name: credential.user_name.clone(),
            user_display_name: credential.user_display_name.clone(),
            key: store::StoredTpmKey {
                private: credential.key.private.clone(),
                public: credential.key.public.clone(),
                public_key_x: credential.key.public_key_x.clone(),
                public_key_y: credential.key.public_key_y.clone(),
                auth_value: credential.key.auth_value.clone(),
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
        session: session::SessionContext::detect(),
        approval: Box::new(AlwaysApprove),
        credentials: credentials
            .into_iter()
            .map(|credential| Credential {
                id: credential.id,
                rp_id: rp_id.to_owned(),
                discoverable: true,
                user_id: Some(1000),
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
        key_agreement: None,
        pin_uv_auth_token: None,
        uv_satisfied: false,
        management: None,
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
    ciborium::into_writer(&body, &mut payload).expect("serialize CTAP request");
    payload
}

fn test_store_dir(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "linux-tpm-fido2-ctap2-test-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn credential_descriptor(id: Vec<u8>) -> Value {
    Value::Map(vec![
        (
            Value::Text("type".to_owned()),
            Value::Text("public-key".to_owned()),
        ),
        (Value::Text("id".to_owned()), Value::Bytes(id)),
    ])
}

fn client_pin_key_agreement(authenticator: &mut Authenticator) -> Vec<(Value, Value)> {
    let response = authenticator.handle_cbor(&ctap_request(
        Ctap2Command::ClientPin,
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
        ]),
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
    mac.finalize().into_bytes()[..16].to_vec()
}

fn management_pin_auth(
    key: &[u8],
    sub_command: i128,
    params: Option<&[(Value, Value)]>,
) -> Vec<u8> {
    let message = management_auth_message(sub_command, params);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(&message);
    mac.finalize().into_bytes()[..16].to_vec()
}

fn options_map(options: &[(&str, bool)]) -> Vec<(Value, Value)> {
    options
        .iter()
        .map(|(key, value)| (Value::Text((*key).to_owned()), Value::Bool(*value)))
        .collect()
}

fn options_text_map(options: &[(&str, &str)]) -> Vec<(Value, Value)> {
    options
        .iter()
        .map(|(key, value)| {
            (
                Value::Text((*key).to_owned()),
                Value::Text((*value).to_owned()),
            )
        })
        .collect()
}
