SET search_path TO app, extensions, public;

CREATE TABLE profile_account_administration (
    request_id uuid PRIMARY KEY,
    target_profile_id uuid NOT NULL,
    account_type varchar(16) NOT NULL,
    account_id uuid NOT NULL REFERENCES identity_accounts(id) ON DELETE RESTRICT,
    email citext NOT NULL,
    display_name varchar(180) NOT NULL,
    mode varchar(16) NOT NULL,
    delivery_status varchar(24) NOT NULL,
    idempotency_key varchar(160) NOT NULL UNIQUE,
    request_hash char(64) NOT NULL,
    actor_account_id uuid NOT NULL REFERENCES identity_accounts(id) ON DELETE RESTRICT,
    reason varchar(500) NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_profile_account_admin_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_account_admin_mode CHECK (mode IN ('DIRECT', 'INVITATION')),
    CONSTRAINT ck_profile_account_admin_delivery CHECK (delivery_status IN ('NOT_REQUIRED', 'PENDING', 'SENT', 'RETRY_REQUIRED')),
    CONSTRAINT ck_profile_account_admin_reason CHECK (char_length(reason) BETWEEN 8 AND 500),
    UNIQUE (account_type, account_id),
    UNIQUE (account_type, target_profile_id)
);

CREATE INDEX ix_profile_account_admin_target
    ON profile_account_administration(account_type, target_profile_id, created_at DESC);

COMMENT ON TABLE profile_account_administration IS
    'Audited Backoffice command that creates an unlinked portal account for a known profile. Linking still requires the protected CCCD/email proof flow.';
