SET search_path TO app, extensions, public;

ALTER TABLE identity_accounts DROP CONSTRAINT ck_identity_account_status;
ALTER TABLE identity_accounts ADD CONSTRAINT ck_identity_account_status
    CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'CLOSED'));

CREATE TABLE account_lifecycle_requests (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    target_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    action varchar(16) NOT NULL CHECK (action IN ('LOCK', 'DISABLE', 'RECOVER')),
    previous_status varchar(24) NOT NULL,
    resulting_status varchar(24) NOT NULL,
    expected_version bigint NOT NULL,
    resulting_version bigint,
    reason varchar(500) NOT NULL CHECK (char_length(reason) BETWEEN 8 AND 500),
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE INDEX ix_account_lifecycle_target
    ON account_lifecycle_requests(target_account_id, created_at DESC);
CREATE INDEX ix_account_lifecycle_actor
    ON account_lifecycle_requests(actor_account_id, created_at DESC);

COMMENT ON TABLE account_lifecycle_requests IS
    'Idempotency and immutable audit ledger for Keycloak-backed Backoffice account lifecycle actions.';
