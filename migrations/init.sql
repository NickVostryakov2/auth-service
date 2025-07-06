CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36),
    token_hash TEXT,
    user_agent TEXT,
    client_ip TEXT,
    expires_at BIGINT,
    used BOOLEAN DEFAULT FALSE
);