SET search_path TO app, extensions, public;

CREATE TABLE session_revocation_requests (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    target_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    keycloak_session_id varchar(128) NOT NULL,
    reason varchar(500) NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT ck_session_revocation_reason CHECK (char_length(reason) BETWEEN 8 AND 500)
);

CREATE INDEX ix_session_revocation_target
    ON session_revocation_requests(target_account_id, created_at DESC);
CREATE INDEX ix_session_revocation_actor
    ON session_revocation_requests(actor_account_id, created_at DESC);

COMMENT ON TABLE session_revocation_requests IS
    'Idempotency and audit ledger for Keycloak session revocation; no token or local session state is stored.';
