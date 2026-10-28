use ciborium::{cbor, value::Value};

use super::cbor_codec::byte_string;
use sha2::{Digest, Sha256};

use super::{AAGUID, COSE_ALG_ES256};
use crate::tpm;

pub(super) fn make_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<(&[u8], &Value)>,
    extensions: Option<&Value>,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(flags | if extensions.is_some() { 0x80 } else { 0x00 });
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((credential_id, public_key)) = attested_credential_data {
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        ciborium::into_writer(public_key, &mut auth_data).expect("serializing static COSE key");
    }

    if let Some(extensions) = extensions {
        ciborium::into_writer(extensions, &mut auth_data).expect("serializing CTAP2 extensions");
    }

    auth_data
}

pub(super) fn cose_credential_public_key(key: &tpm::TpmCredential) -> Value {
    cose_public_key_coordinates(key.public_key_x.clone(), key.public_key_y.clone())
}

pub(super) fn cose_public_key_coordinates(x: Vec<u8>, y: Vec<u8>) -> Value {
    cbor!({
        1 => 2,
        3 => COSE_ALG_ES256,
        -1 => 1,
        -2 => byte_string(x),
        -3 => byte_string(y),
    })
    .expect("COSE credential public key")
}

pub(super) fn cose_key_agreement_coordinates(x: Vec<u8>, y: Vec<u8>) -> Value {
    cbor!({
        1 => 2,
        3 => -25,
        -1 => 1,
        -2 => byte_string(x),
        -3 => byte_string(y),
    })
    .expect("COSE key agreement")
}
