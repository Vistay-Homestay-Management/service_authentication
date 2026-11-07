SET search_path TO app, extensions, public;

CREATE TABLE host_invitations (
    invitation_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity_accounts(id) ON DELETE RESTRICT,
    realm varchar(80) NOT NULL DEFAULT 'vistay-host',
    subject_type varchar(16) NOT NULL DEFAULT 'HOST',
    keycloak_subject varchar(128) NOT NULL,
    email citext NOT NULL,
    display_name varchar(180) NOT NULL,
    phone varchar(40),
    request_hash char(64) NOT NULL,
    idempotency_key varchar(160) NOT NULL UNIQUE,
    state varchar(24) NOT NULL DEFAULT 'INVITED',
    action_dispatch_status varchar(24) NOT NULL DEFAULT 'PENDING',
    expires_at timestamptz NOT NULL,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    reason varchar(500) NOT NULL,
    property_id uuid NOT NULL,
    branch_id uuid NOT NULL,
    ownership_term varchar(16) NOT NULL DEFAULT 'OWNED',
    correlation_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    CONSTRAINT ck_host_invitation_realm CHECK (realm = 'vistay-host'),
    CONSTRAINT ck_host_invitation_subject_type CHECK (subject_type = 'HOST'),
    CONSTRAINT ck_host_invitation_state CHECK (
        state IN ('INVITED', 'ACTIONS_PENDING', 'ACTIVE', 'EXPIRED', 'CANCELLED')
    ),
    CONSTRAINT ck_host_invitation_dispatch CHECK (
        action_dispatch_status IN ('PENDING', 'SENT', 'RETRY_REQUIRED')
    ),
    CONSTRAINT ck_host_invitation_ownership CHECK (ownership_term = 'OWNED'),
    CONSTRAINT ck_host_invitation_reason CHECK (char_length(reason) BETWEEN 8 AND 500),
    CONSTRAINT ck_host_invitation_version CHECK (version > 0),
    UNIQUE (realm, email),
    UNIQUE (realm, keycloak_subject)
);

CREATE INDEX ix_host_invitation_actor
    ON host_invitations(actor_account_id, created_at DESC);
CREATE INDEX ix_host_invitation_expiry
    ON host_invitations(state, expires_at);

CREATE TABLE host_invitation_resends (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    invitation_id uuid NOT NULL REFERENCES host_invitations(invitation_id) ON DELETE RESTRICT,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id),
    reason varchar(500) NOT NULL,
    correlation_id uuid NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PENDING',
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT ck_host_resend_status CHECK (status IN ('PENDING', 'COMPLETED', 'RETRY_REQUIRED')),
    CONSTRAINT ck_host_resend_reason CHECK (char_length(reason) BETWEEN 8 AND 500)
);

CREATE INDEX ix_host_resend_invitation
    ON host_invitation_resends(invitation_id, created_at DESC);

CREATE TABLE host_invitation_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    invitation_id uuid NOT NULL REFERENCES host_invitations(invitation_id) ON DELETE RESTRICT,
    actor_account_id uuid REFERENCES identity_accounts(id),
    action varchar(64) NOT NULL,
    previous_state varchar(24),
    resulting_state varchar(24) NOT NULL,
    reason varchar(500) NOT NULL,
    correlation_id uuid NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_host_audit_details CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT ck_host_audit_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);

CREATE INDEX ix_host_invitation_audit_invitation
    ON host_invitation_audit(invitation_id, created_at DESC);

COMMENT ON TABLE host_invitations IS
    'Replay-safe Host invitation projection; Keycloak owns credentials and action tokens.';
COMMENT ON TABLE host_invitation_resends IS
    'Idempotency ledger for Host execute-actions email resend requests.';
COMMENT ON TABLE host_invitation_audit IS
    'Append-only security audit for Host invitation and activation transitions.';
