SET search_path TO app, extensions, public;

ALTER TABLE provisioning_requests
    ALTER COLUMN idempotency_key TYPE varchar(160);

CREATE TABLE backoffice_account_invitations (
    invitation_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity_accounts(id) ON DELETE RESTRICT,
    keycloak_subject varchar(128) NOT NULL,
    email citext NOT NULL,
    display_name varchar(180) NOT NULL,
    request_hash char(64) NOT NULL,
    idempotency_key varchar(160) NOT NULL UNIQUE,
    action_dispatch_status varchar(24) NOT NULL DEFAULT 'PENDING',
    expires_at timestamptz NOT NULL,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    reason varchar(500) NOT NULL,
    correlation_id uuid NOT NULL,
    action_dispatched_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_backoffice_invitation_dispatch CHECK (
        action_dispatch_status IN ('PENDING', 'SENT', 'RETRY_REQUIRED')
    ),
    CONSTRAINT ck_backoffice_invitation_reason CHECK (char_length(reason) BETWEEN 8 AND 500),
    CONSTRAINT ck_backoffice_invitation_expiry CHECK (expires_at > created_at),
    UNIQUE (email),
    UNIQUE (keycloak_subject)
);

CREATE INDEX ix_backoffice_invitation_actor
    ON backoffice_account_invitations(actor_account_id, created_at DESC);
CREATE INDEX ix_backoffice_invitation_delivery
    ON backoffice_account_invitations(action_dispatch_status, expires_at);

COMMENT ON TABLE backoffice_account_invitations IS
    'Replay-safe employee invitations; Keycloak owns email verification, passwords and action tokens.';
