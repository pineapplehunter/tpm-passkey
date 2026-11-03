CREATE TABLE credential_metadata (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id TEXT NOT NULL,
    user_handle BLOB NOT NULL,
    user_name TEXT,
    user_display_name TEXT,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credential_keyslots (
    keyslot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id BLOB NOT NULL REFERENCES credential_metadata(credential_id) ON DELETE CASCADE,
    slot_kind TEXT NOT NULL CHECK (slot_kind IN ('primary', 'recovery')),
    slot_label TEXT,
    policy_selection TEXT,
    policy_digest BLOB,
    tpm_private BLOB NOT NULL,
    tpm_public BLOB NOT NULL,
    public_key_x BLOB NOT NULL,
    public_key_y BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_id, slot_kind)
);

CREATE TABLE credential_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyslot_id INTEGER NOT NULL REFERENCES credential_keyslots(keyslot_id) ON DELETE CASCADE,
    token_type TEXT NOT NULL CHECK (token_type IN ('passphrase')),
    label TEXT,
    passphrase_salt BLOB NOT NULL,
    passphrase_hash BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (keyslot_id, token_type)
);

CREATE INDEX credential_metadata_rp_id_idx ON credential_metadata(rp_id);
CREATE INDEX credential_keyslots_credential_id_idx ON credential_keyslots(credential_id);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);

INSERT INTO credential_metadata (
    credential_id, rp_id, user_handle, user_name, user_display_name, sign_count
)
SELECT credential_id, rp_id, user_handle, user_name, user_display_name, sign_count
FROM credentials;

INSERT INTO credential_keyslots (
    credential_id, slot_kind, slot_label, policy_selection, policy_digest,
    tpm_private, tpm_public, public_key_x, public_key_y
)
SELECT k.credential_id, 'primary', NULL, c.policy_selection, c.policy_digest,
       k.tpm_private, k.tpm_public, k.public_key_x, k.public_key_y
FROM tpm_keys k
JOIN credentials c ON c.credential_id = k.credential_id;

INSERT INTO credential_keyslots (
    credential_id, slot_kind, slot_label, policy_selection, policy_digest,
    tpm_private, tpm_public, public_key_x, public_key_y
)
SELECT credential_id, 'recovery', recovery_label, NULL, NULL,
       recovery_tpm_private, recovery_tpm_public, recovery_public_key_x, recovery_public_key_y
FROM credentials
WHERE recovery_tpm_private IS NOT NULL;

INSERT INTO credential_tokens (
    keyslot_id, token_type, label, passphrase_salt, passphrase_hash
)
SELECT r.keyslot_id, 'passphrase', r.slot_label, c.recovery_passphrase_salt, c.recovery_passphrase_hash
FROM credential_keyslots r
JOIN credentials c ON c.credential_id = r.credential_id
WHERE r.slot_kind = 'recovery'
  AND c.recovery_passphrase_salt IS NOT NULL
  AND c.recovery_passphrase_hash IS NOT NULL;
