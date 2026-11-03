CREATE TABLE credentials (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id TEXT NOT NULL,
    user_handle BLOB NOT NULL,
    user_name TEXT,
    user_display_name TEXT,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tpm_keys (
    credential_id BLOB PRIMARY KEY NOT NULL REFERENCES credentials(credential_id) ON DELETE CASCADE,
    tpm_private BLOB NOT NULL,
    tpm_public BLOB NOT NULL,
    public_key_x BLOB NOT NULL,
    public_key_y BLOB NOT NULL
);

CREATE INDEX credentials_rp_id_idx ON credentials(rp_id);
