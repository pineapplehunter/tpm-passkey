use super::*;

#[test]
fn rejects_noncanonical_duplicate_tagged_trailing_and_deep_cbor() {
    let invalid: &[&[u8]] = &[
        &[0xbf, 0xff],                                     // indefinite map
        &[0xa1, 1, 0x9f, 0xff],                            // indefinite nested array
        &[0xa1, 1, 0x5f, 0x41, 0, 0xff],                   // indefinite string
        &[0xb8, 0],                                        // nonminimal map length
        &[0xa1, 0x18, 1, 0],                               // nonminimal integer key
        &[0xa1, 1, 0x18, 0],                               // nonminimal integer value
        &[0xa1, 1, 0x58, 0],                               // nonminimal string length
        &[0xa2, 2, 0, 1, 0],                               // wrong key order
        &[0xa2, 1, 0, 1, 1],                               // duplicate key
        &[0xa1, 1, 0xa2, 1, 0, 1, 1],                      // nested duplicate
        &[0xa1, 1, 0xc0, 0],                               // forbidden CBOR tag
        &[0xa0, 0],                                        // trailing second object
        &[0xa1, 1, 0x61, 0xff],                            // invalid UTF-8
        &[0xa1, 1, 0x44, 0],                               // truncated string
        &[0xa1, 1, 0xa1, 1, 0xa1, 1, 0xa1, 1, 0xa1, 1, 0], // depth 5
    ];
    for input in invalid {
        assert_eq!(
            decode_map(input),
            Err(ErrorStatus::InvalidCbor),
            "{input:02x?}"
        );
    }
    assert!(decode_map(&[0xa1, 1, 0xa1, 1, 0xa1, 1, 0xa1, 1, 0]).is_ok());
    assert_eq!(decode_map(&[0x80]), Err(ErrorStatus::CborUnexpectedType));
    // Canonical unknown keys remain valid; command handlers ignore their values.
    assert!(decode_map(&[0xa2, 1, 0, 0x18, 0xff, 0xf5]).is_ok());
}

#[test]
fn accepts_all_float_widths_and_preserves_authenticated_parameter_bytes() {
    for float in [
        vec![0xf9, 0x3e, 0x00],
        vec![0xfa, 0x3f, 0xc0, 0, 0],
        vec![0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0],
    ] {
        let mut body = vec![0xa1, 2];
        body.extend_from_slice(&float);
        assert!(decode_map(&body).is_ok());
        assert_eq!(encoded_map_value(&body, 2).unwrap(), Some(float.as_slice()));
        assert_eq!(encoded_map_value(&body, 3).unwrap(), None);
    }
}

#[test]
fn rejects_requests_exceeding_the_advertised_message_size() {
    let store = std::env::temp_dir().join(format!("ctap-message-limit-{}", std::process::id()));
    let mut authenticator = Authenticator::new(store, None);
    assert_eq!(
        authenticator.handle_cbor(&vec![0; MAX_MSG_SIZE + 1]),
        vec![0x39]
    );
}
