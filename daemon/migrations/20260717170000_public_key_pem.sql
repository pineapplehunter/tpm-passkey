-- Switch public_key column from BLOB (raw SEC.1 point) to TEXT (PEM-encoded SPKI)
-- Since SQLite lacks ALTER COLUMN, we recreate the table.
-- Data loss is acceptable at this development stage.

DROP TABLE IF EXISTS credential_tokens;
DROP TABLE IF EXISTS credential_keyslots;

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
    public_key TEXT NOT NULL,
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

CREATE INDEX credential_keyslots_credential_id_idx ON credential_keyslots(credential_id);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);
