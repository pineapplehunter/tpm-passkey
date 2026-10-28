ALTER TABLE credential_tokens ADD COLUMN last_used TEXT;
ALTER TABLE credential_tokens ADD COLUMN used_count INTEGER NOT NULL DEFAULT 0
    CHECK (used_count >= 0);
