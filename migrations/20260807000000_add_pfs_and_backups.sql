CREATE TABLE olm_identity_keys (
    client_id UUID PRIMARY KEY,
    identity_key TEXT NOT NULL,
    signed_pre_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE olm_one_time_keys (
    key_id SERIAL PRIMARY KEY,
    client_id UUID NOT NULL,
    key_value TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE cloud_backups (
    client_id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
);
