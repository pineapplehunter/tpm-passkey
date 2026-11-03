use super::*;

fn bytes(data: impl AsRef<[u8]>) -> Value {
    Value::Bytes(data.as_ref().to_vec())
}

fn request(value: Value) -> Vec<u8> {
    let mut body = vec![Ctap2Command::ClientPin.into()];
    ciborium::into_writer(&value, &mut body).unwrap();
    body
}

fn response_map(bytes: &[u8]) -> Vec<(Value, Value)> {
    assert_eq!(bytes[0], 0);
    let Value::Map(map) = ciborium::from_reader(&bytes[1..]).unwrap() else {
        panic!("expected response map")
    };
    map
}

fn map_bytes(map: &[(Value, Value)], key: i128) -> &[u8] {
    map_value(map, key).unwrap().as_bytes().unwrap()
}

fn client_key(secret: &EphemeralSecret) -> Value {
    let point = secret.public_key().to_sec1_bytes();
    cose_key_agreement_coordinates(point[1..33].to_vec(), point[33..65].to_vec())
}

fn shared_keys(auth: &mut Authenticator, secret: &EphemeralSecret) -> ([u8; 32], [u8; 32]) {
    let server = auth.handle_cbor(&request(cbor!({ 1 => 1, 2 => 2 }).unwrap()));
    let agreement = response_map(&server);
    let key = map_map(&agreement, 1).unwrap();
    let server_key = parse_key_agreement(key).unwrap();
    let shared = secret.diffie_hellman(&server_key);
    derive_pin_uv_keys(1, shared.raw_secret_bytes().as_slice()).unwrap()
}

fn auth_param(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes()[..16].to_vec()
}

#[test]
fn protocol_one_independent_sha256_and_cbc_vectors() {
    assert_eq!(
        hex::encode(derive_pin_uv_keys(1, &[0x42; 32]).unwrap().0),
        "425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c"
    );
    assert_eq!(
        derive_pin_uv_keys(1, &[0x42; 32]).unwrap().0,
        derive_pin_uv_keys(1, &[0x42; 32]).unwrap().1
    );
    // NIST AES-256 ECB vector: protocol 1 CBC with a zero IV has this exact first block.
    let key: [u8; 32] =
        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap()
            .try_into()
            .unwrap();
    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    assert_eq!(
        hex::encode(encrypt_aes_protocol(1, &key, &plaintext).unwrap()),
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
    );
    let full_mac = {
        let mut mac = HmacSha256::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        mac.finalize().into_bytes()
    };
    assert_eq!(
        hex::encode(&full_mac[..16]),
        "b0344c61d8db38535ca8afceaf0bf12b"
    );
}

#[test]
fn protocol_one_set_change_token_and_cross_protocol_auth_regression() {
    let dir = std::env::temp_dir().join(format!("ctap-proto1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut auth = Authenticator::new(dir.clone(), None);

    let secret = EphemeralSecret::generate();
    let (aes, mac) = shared_keys(&mut auth, &secret);
    let mut padded = b"1234".to_vec();
    padded.resize(64, 0);
    let enc_pin = encrypt_aes_protocol(1, &aes, &padded).unwrap();
    let set = auth.handle_cbor(&request(
        cbor!({
            1 => 1, 2 => 3, 3 => client_key(&secret),
            4 => bytes(auth_param(&mac, &enc_pin)), 5 => bytes(enc_pin),
        })
        .unwrap(),
    ));
    assert_eq!(set, vec![0, 0xa0]);

    let change_secret = EphemeralSecret::generate();
    let (aes, mac) = shared_keys(&mut auth, &change_secret);
    let mut new_pin = b"5678".to_vec();
    new_pin.resize(64, 0);
    let enc_new = encrypt_aes_protocol(1, &aes, &new_pin).unwrap();
    let old_hash = Sha256::digest(b"1234");
    let enc_hash = encrypt_aes_protocol(1, &aes, &old_hash[..16]).unwrap();
    let message = [enc_new.as_slice(), enc_hash.as_slice()].concat();
    let changed = auth.handle_cbor(&request(
        cbor!({
            1 => 1, 2 => 4, 3 => client_key(&change_secret),
            4 => bytes(auth_param(&mac, &message)), 5 => bytes(enc_new), 6 => bytes(enc_hash),
        })
        .unwrap(),
    ));
    assert_eq!(changed, vec![0, 0xa0]);

    let token_secret = EphemeralSecret::generate();
    let (aes, _) = shared_keys(&mut auth, &token_secret);
    let new_hash = Sha256::digest(b"5678");
    let encrypted_hash = encrypt_aes_protocol(1, &aes, &new_hash[..16]).unwrap();
    let token_response = auth.handle_cbor(&request(
        cbor!({
            1 => 1, 2 => 9, 3 => client_key(&token_secret),
            6 => bytes(encrypted_hash), 9 => 1, 10 => "example.com",
        })
        .unwrap(),
    ));
    let token_response = response_map(&token_response);
    assert_eq!(token_response.len(), 1);
    let token = decrypt_aes_protocol(1, &aes, map_bytes(&token_response, 2)).unwrap();
    assert_eq!(token.len(), 32);
    let message = [0x5a; 32];
    let token_key: &[u8; 32] = token.as_slice().try_into().unwrap();
    let signature = auth_param(token_key, &message);
    assert_eq!(signature.len(), 16);
    assert_eq!(
        auth.validate_pin_uv_auth(
            Some(1),
            Some(&signature),
            &message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some("example.com")
        ),
        Ok(true)
    );
    // Even a correctly sized, valid Protocol 2 MAC using this Protocol 1
    // token must be rejected; a length-only check would miss this.
    let mut mac = HmacSha256::new_from_slice(token_key).unwrap();
    mac.update(&message);
    let cross_protocol_signature = mac.finalize().into_bytes();
    assert_eq!(
        auth.validate_pin_uv_auth(
            Some(2),
            Some(&cross_protocol_signature),
            &message,
            Ctap2PermissionFlags::MAKE_CREDENTIAL,
            Some("example.com")
        ),
        Err(ErrorStatus::PinAuthInvalid)
    );
    let _ = std::fs::remove_dir_all(dir);
}
