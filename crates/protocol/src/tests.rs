use super::*;
use ciborium::cbor;
use std::{
    fs::File,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
};
use zbus::zvariant::OwnedFd;

fn descriptor(bytes: &[u8], seal: bool) -> OwnedFd {
    let raw = unsafe {
        libc::memfd_create(
            c"protocol-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(raw >= 0);
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes).unwrap();
    if seal {
        assert_eq!(
            unsafe {
                libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SEAL,
                )
            },
            0
        );
    }
    std::os::fd::OwnedFd::from(file).into()
}

#[test]
fn sealed_secret_roundtrip_ignores_shared_file_offset() {
    let request = ManagementRequest::UnlockRecovery {
        passphrase: zeroize::Zeroizing::new("test-only-secret".into()),
    };
    let fd = transport::seal_request(&request).unwrap();
    assert!(unsafe { libc::lseek(fd.as_raw_fd(), 9999, libc::SEEK_SET) } >= 0);
    let ManagementRequest::UnlockRecovery { ref passphrase } =
        transport::read_request(&fd).unwrap()
    else {
        panic!("wrong operation")
    };
    assert_eq!(passphrase.as_str(), "test-only-secret");
    assert!(unsafe { libc::write(fd.as_raw_fd(), c"x".as_ptr().cast(), 1) } < 0);
    assert!(!format!("{request:?}").contains("test-only-secret"));
}

#[test]
fn unsealed_empty_and_oversized_descriptors_are_rejected() {
    let mut encoded = Vec::new();
    ciborium::into_writer(&ManagementRequest::ShowConfig, &mut encoded).unwrap();
    assert!(transport::read_request(&descriptor(&encoded, false)).is_err());
    assert!(transport::read_request(&descriptor(&[], true)).is_err());
    assert!(
        transport::read_request(&descriptor(
            &vec![0; transport::MAX_REQUEST_BYTES + 1],
            true
        ))
        .is_err()
    );
}

#[test]
fn sockets_are_rejected_without_reading_them() {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd: OwnedFd = std::os::fd::OwnedFd::from(socket).into();
    assert!(transport::read_request(&fd).is_err());
}

#[test]
fn malformed_and_trailing_data_do_not_echo_secret_bytes() {
    let secret = b"test-only-sensitive-malformed-data";
    let error = transport::read_request(&descriptor(secret, true))
        .unwrap_err()
        .to_string();
    assert_eq!(error, "invalid management request");
    let mut encoded = Vec::new();
    ciborium::into_writer(&ManagementRequest::ShowConfig, &mut encoded).unwrap();
    encoded.extend_from_slice(secret);
    assert!(transport::read_request(&descriptor(&encoded, true)).is_err());
}

#[test]
fn bounded_serialization_and_partial_secret_decoding_fail_closed() {
    let oversized = ManagementRequest::UpdatePassphrase {
        old_passphrase: Some(zeroize::Zeroizing::new("a".repeat(6000))),
        new_passphrase: zeroize::Zeroizing::new("b".repeat(12000)),
    };
    assert_eq!(
        transport::seal_request(&oversized).unwrap_err().to_string(),
        "management request too large"
    );
    // Externally tagged decoding visits secret fields directly; each field is
    // guarded even when a later field fails, rather than waiting for enum Drop.
    let partial = ciborium::cbor!({"update-passphrase" => {
        "old_passphrase" => "test-only-partially-decoded-secret", "new_passphrase" => 7
    }})
    .unwrap();
    let mut encoded = Vec::new();
    ciborium::into_writer(&partial, &mut encoded).unwrap();
    assert_eq!(
        transport::read_request(&descriptor(&encoded, true))
            .unwrap_err()
            .to_string(),
        "invalid management request"
    );
    let valid = ManagementRequest::UpdatePassphrase {
        old_passphrase: Some(zeroize::Zeroizing::new("x".repeat(6000))),
        new_passphrase: zeroize::Zeroizing::new("new".into()),
    };
    assert_eq!(
        transport::read_request(&transport::seal_request(&valid).unwrap())
            .unwrap()
            .operation(),
        "update-passphrase"
    );
}

#[test]
fn approval_context_is_bounded_and_has_known_operation() {
    let mut context = ApprovalContext {
        operation: "register".into(),
        rp_id: "example.test".into(),
        rp_name: String::new(),
        account_name: String::new(),
        account_id: String::new(),
        credential_count: 1,
    };
    assert!(context.validate());
    context.rp_id.clear();
    assert!(!context.validate());
    context.operation = "selection".into();
    assert!(context.validate());
    context.rp_name = "a".repeat(2049);
    assert!(!context.validate());
    context.rp_name.clear();
    context.operation = "unsupported".into();
    assert!(!context.validate());
}
