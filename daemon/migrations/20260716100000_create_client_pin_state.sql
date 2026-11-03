CREATE TABLE client_pin_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    pin_salt BLOB NOT NULL,
    pin_verifier BLOB NOT NULL,
    retries INTEGER NOT NULL CHECK (retries >= 0 AND retries <= 8),
    integrity_mac BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
