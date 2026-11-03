-- Breaking security-format change: old records contain reusable plaintext
-- recovery authorization values. They cannot be securely upgraded without the
-- user's phrase, and previous credentials are intentionally discarded.
DELETE FROM credential_metadata;
DELETE FROM daemon_config WHERE key = 'daemon_passphrase';

DROP TABLE credential_tokens;
CREATE TABLE credential_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyslot_id INTEGER NOT NULL REFERENCES credential_keyslots(keyslot_id) ON DELETE CASCADE,
    token_type TEXT NOT NULL CHECK (token_type = 'passphrase'),
    label TEXT,
    encrypted_auth BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (keyslot_id, token_type)
);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);
