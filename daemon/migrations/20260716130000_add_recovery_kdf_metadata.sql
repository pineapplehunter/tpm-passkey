ALTER TABLE credential_tokens ADD COLUMN kdf_algorithm TEXT NOT NULL DEFAULT 'pbkdf2-sha256';
ALTER TABLE credential_tokens ADD COLUMN kdf_memory_kib INTEGER;
ALTER TABLE credential_tokens ADD COLUMN kdf_iterations INTEGER;
ALTER TABLE credential_tokens ADD COLUMN kdf_parallelism INTEGER;
