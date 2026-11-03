use super::*;

struct Outcome(approval::ApprovalOutcome);
impl approval::UserApproval for Outcome {
    fn approve(&self, _: &str) -> bool {
        false
    }
    fn approve_controlled(
        &self,
        _: &str,
        _: &approval::ApprovalControl,
    ) -> approval::ApprovalOutcome {
        self.0
    }
}

fn credential() -> Credential {
    Credential {
        id: vec![1],
        rp_id: "example.test".into(),
        discoverable: true,
        user_handle: vec![1],
        user_name: None,
        user_display_name: None,
        key: tpm::TpmCredential {
            private: vec![],
            public: vec![],
            public_key_x: vec![],
            public_key_y: vec![],
            auth_value: None,
        },
        policy: None,
        migration_authority: None,
        sign_count: 0,
    }
}

fn body(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
}
fn make_request() -> Value {
    cbor!({1 => byte_string([0; 32]), 2 => {"id" => "example.test"},
        3 => {"id" => byte_string([2])}, 4 => [{"alg" => -7, "type" => "public-key"}],
        5 => [{"id" => byte_string([1]), "type" => "public-key"}]})
    .unwrap()
}

#[test]
fn exclusion_returns_excluded_on_timeout_without_consuming_token() {
    for outcome in [
        approval::ApprovalOutcome::Approved,
        approval::ApprovalOutcome::TimedOut,
        approval::ApprovalOutcome::Cancelled,
    ] {
        let mut auth = Authenticator::default();
        auth.credentials.push(credential());
        auth.approval = Box::new(Outcome(outcome));
        auth.pin_uv_auth_token = Some(PinUvAuthToken {
            protocol: 2,
            value: vec![42; 32],
            permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
            rp_id: None,
            issued_at: Instant::now(),
            first_used_at: Some(Instant::now()),
            user_present_until: None,
        });
        let expected = if outcome == approval::ApprovalOutcome::Cancelled {
            ErrorStatus::KeepaliveCancel
        } else {
            ErrorStatus::CredentialExcluded
        };
        assert_eq!(auth.make_credential(&body(make_request())), Err(expected));
        assert_eq!(
            auth.pin_uv_auth_token.as_ref().unwrap().permissions,
            Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT
        );
    }
}

#[test]
fn authenticated_exclusion_preserves_cached_presence_and_permissions() {
    let mut auth = Authenticator::default();
    auth.credentials.push(credential());
    auth.approval = Box::new(Outcome(approval::ApprovalOutcome::Cancelled));
    let deadline = Instant::now() + Duration::from_secs(20);
    auth.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: vec![42; 32],
        permissions: Ctap2PermissionFlags::MAKE_CREDENTIAL,
        rp_id: Some("example.test".into()),
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: Some(deadline),
    });
    let mut mac = HmacSha256::new_from_slice(&[42; 32]).unwrap();
    mac.update(&[0; 32]);
    let mut request = make_request();
    request.as_map_mut().unwrap().extend([
        (
            cbor!(8).unwrap(),
            byte_string(mac.finalize().into_bytes().to_vec()),
        ),
        (cbor!(9).unwrap(), cbor!(2).unwrap()),
    ]);
    assert_eq!(
        auth.make_credential(&body(request)),
        Err(ErrorStatus::CredentialExcluded)
    );
    let token = auth.pin_uv_auth_token.as_ref().unwrap();
    assert_eq!(token.permissions, Ctap2PermissionFlags::MAKE_CREDENTIAL);
    assert_eq!(token.user_present_until, Some(deadline));
}

#[test]
fn management_does_not_consume_permissions_but_expiry_discards_continuation() {
    let mut auth = Authenticator::default();
    auth.credentials.push(credential());
    let mut second = credential();
    second.rp_id = "second.test".into();
    auth.credentials.push(second);
    auth.pin_uv_auth_token = Some(PinUvAuthToken {
        protocol: 2,
        value: vec![42; 32],
        permissions: Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT,
        rp_id: None,
        issued_at: Instant::now(),
        first_used_at: None,
        user_present_until: None,
    });
    for command in [1u8, 2] {
        let mut mac = HmacSha256::new_from_slice(&[42; 32]).unwrap();
        mac.update(&[command]);
        assert!(
            auth.credential_management(&body(
                cbor!({1 => command, 3 => 2,
            4 => byte_string(mac.finalize().into_bytes().to_vec())})
                .unwrap()
            ))
            .is_ok()
        );
        assert_eq!(
            auth.pin_uv_auth_token.as_ref().unwrap().permissions,
            Ctap2PermissionFlags::CREDENTIAL_MANAGEMENT
        );
    }
    auth.pin_uv_auth_token.as_mut().unwrap().issued_at = Instant::now() - Duration::from_secs(601);
    assert_eq!(
        auth.credential_management(&body(cbor!({1 => 3}).unwrap())),
        Err(ErrorStatus::NotAllowed)
    );
    assert!(auth.management.is_none());
}

#[test]
fn exclusion_precedes_resident_capacity_check() {
    let mut auth = Authenticator::default();
    auth.approval = Box::new(Outcome(approval::ApprovalOutcome::Approved));
    auth.credentials = vec![credential(); MAX_RESIDENT_CREDENTIALS];
    let mut request = make_request();
    request
        .as_map_mut()
        .unwrap()
        .push((cbor!(7).unwrap(), cbor!({"rk" => true}).unwrap()));
    assert_eq!(
        auth.make_credential(&body(request)),
        Err(ErrorStatus::CredentialExcluded)
    );
}

#[test]
fn make_and_get_distinguish_wrong_required_type_from_missing_parameter() {
    for key in 1..=4 {
        let mut auth = Authenticator::default();
        let mut request = make_request();
        let map = request.as_map_mut().unwrap();
        map.iter_mut()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
            .unwrap()
            .1 = Value::Null;
        assert_eq!(
            auth.make_credential(&body(request)),
            Err(ErrorStatus::CborUnexpectedType)
        );
    }
    for request in [
        cbor!({1 => 7, 2 => byte_string([0; 32])}).unwrap(),
        cbor!({1 => "example.test", 2 => 7}).unwrap(),
    ] {
        assert_eq!(
            Authenticator::default().get_assertion(&body(request)),
            Err(ErrorStatus::CborUnexpectedType)
        );
    }
    assert_eq!(
        Authenticator::default().make_credential(&body(cbor!({}).unwrap())),
        Err(ErrorStatus::MissingParameter)
    );
}

#[test]
fn protocol_without_auth_param_does_not_require_a_token() {
    let mut auth = Authenticator::default();
    assert_eq!(
        auth.get_assertion(&body(
            cbor!({1 => "example.test", 2 => byte_string([0; 32]), 7 => 99}).unwrap()
        )),
        Err(ErrorStatus::NoCredentials)
    );
    auth.credentials.push(credential());
    auth.approval = Box::new(Outcome(approval::ApprovalOutcome::Approved));
    let mut request = make_request();
    request
        .as_map_mut()
        .unwrap()
        .push((cbor!(9).unwrap(), cbor!(99).unwrap()));
    assert_eq!(
        auth.make_credential(&body(request)),
        Err(ErrorStatus::CredentialExcluded)
    );
}
