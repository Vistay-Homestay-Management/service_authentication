SET search_path TO app, extensions, public;

-- Credentials and interactive sessions are now owned by Keycloak. These rows
-- are a business/audit projection only; no password or token is stored here.
CREATE TABLE identity_accounts (
    id uuid PRIMARY KEY,
    realm varchar(80) NOT NULL,
    subject varchar(128) NOT NULL,
    account_type varchar(16) NOT NULL,
    email citext NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_identity_account_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_identity_account_status CHECK (status IN ('ACTIVE', 'DISABLED', 'CLOSED')),
    UNIQUE (realm, subject),
    UNIQUE (realm, email)
);

CREATE TABLE provisioning_requests (
    idempotency_key varchar(120) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    identity_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE INDEX ix_provisioning_request_account
    ON provisioning_requests(identity_account_id, created_at DESC);

COMMENT ON TABLE identity_accounts IS
    'Keycloak subject projection; legacy V2 credential tables are retained only until the approved dev rebaseline gate.';
