DROP TABLE IF EXISTS credential_tokens;
DROP TABLE IF EXISTS credential_keyslots;
DROP TABLE IF EXISTS credential_metadata;
DROP TABLE IF EXISTS client_pin_state;
DROP TABLE IF EXISTS daemon_config;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS tpm_keys;

CREATE TABLE credential_metadata (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id TEXT NOT NULL,
    user_handle BLOB NOT NULL,
    user_name TEXT,
    user_display_name TEXT,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    user_id INTEGER,
    integrity_mac BLOB,
    discoverable INTEGER NOT NULL DEFAULT 1 CHECK (discoverable IN (0, 1)),
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
    policy_ref BLOB,
    authority_name BLOB,
    authority_signature BLOB,
    policy_version INTEGER NOT NULL DEFAULT 1,
    tpm_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_id, slot_kind)
);

CREATE TABLE credential_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyslot_id INTEGER NOT NULL REFERENCES credential_keyslots(keyslot_id) ON DELETE CASCADE,
    token_type TEXT NOT NULL CHECK (token_type IN ('passphrase')),
    label TEXT,
    kdf_params TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (keyslot_id, token_type)
);

CREATE TABLE client_pin_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    pin_salt BLOB NOT NULL,
    pin_verifier BLOB NOT NULL,
    retries INTEGER NOT NULL CHECK (retries >= 0 AND retries <= 8),
    integrity_mac BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE daemon_config (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX credential_metadata_rp_id_idx ON credential_metadata(rp_id);
CREATE INDEX credential_metadata_user_id_idx ON credential_metadata(user_id);
CREATE INDEX credential_metadata_owner_rp_discoverable_idx ON credential_metadata(user_id, rp_id, discoverable);
CREATE INDEX credential_keyslots_credential_id_idx ON credential_keyslots(credential_id);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);
