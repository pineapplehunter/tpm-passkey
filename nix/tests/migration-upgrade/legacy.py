"""Build a genuine pre-redesign schema while retaining a real MACed client PIN.

Legacy slot/config names below intentionally match the immutable old schema.
The daemon, not this fixture, must perform the destructive upgrade.
"""
import hashlib
from pathlib import Path
import sqlite3
import sys

STORE = Path('/var/lib/tpm-passkey/credentials.sqlite')
SNAPSHOT = STORE.parent / 'test-pin-snapshot.sqlite'

if sys.argv[1] == 'prepare':
    with sqlite3.connect(STORE) as current, sqlite3.connect(SNAPSHOT) as snapshot:
        current.backup(snapshot)
        pin_columns = [row[1] for row in current.execute('PRAGMA table_info(client_pin_state)')]
        pin = current.execute('SELECT * FROM client_pin_state').fetchone()
        assert pin is not None
    STORE.unlink()
    # The service is stopped and all SQLite connections have been closed.
    for suffix in ('-wal', '-shm'):
        Path(str(STORE) + suffix).unlink(missing_ok=True)
    with sqlite3.connect(STORE) as legacy:
        legacy.execute('PRAGMA foreign_keys = ON')
        legacy.execute('CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)')
        for path in sorted(Path(sys.argv[2]).glob('*.sql')):
            version, description = path.stem.split('_', 1)
            if int(version) >= 20261029090000:
                break
            sql = path.read_bytes()
            legacy.executescript(sql.decode())
            legacy.execute('INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, ?, 1, ?, 0)', (int(version), description.replace('_', ' '), hashlib.sha384(sql).digest()))
        legacy.execute('INSERT INTO client_pin_state (' + ','.join(pin_columns) + ') VALUES (' + ','.join('?' for _ in pin) + ')', pin)
        legacy.execute("INSERT INTO credential_metadata (credential_id, rp_id, user_handle, sign_count) VALUES (X'01', 'legacy.example.test', X'02', 0)")
        legacy.execute("INSERT INTO credential_keyslots (credential_id, slot_kind, tpm_key, public_key) VALUES (X'01', 'recovery', X'03', 'legacy-authority')")
        legacy.execute("INSERT INTO credential_tokens (keyslot_id, token_type, encrypted_auth) VALUES (1, 'passphrase', X'0405')")
        for key in ('recovery_encryption', 'default_pcr_policy'):
            legacy.execute('INSERT INTO daemon_config (key, value) VALUES (?, ?)', (key, b'legacy-config'))
else:
    with sqlite3.connect(STORE) as upgraded, sqlite3.connect(SNAPSHOT) as snapshot:
        assert upgraded.execute('SELECT * FROM client_pin_state').fetchall() == snapshot.execute('SELECT * FROM client_pin_state').fetchall(), 'upgrade altered the client PIN'
        for table in ('credential_metadata', 'credential_keyslots', 'credential_tokens', 'daemon_config'):
            assert upgraded.execute('SELECT count(*) FROM ' + table).fetchone() == (0,), table
    SNAPSHOT.unlink()
    print('destructive upgrade removed old credentials/config and preserved the exact client PIN state')
