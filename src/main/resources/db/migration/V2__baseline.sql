SET search_path TO app, extensions, public;

-- Three account groups are deliberately independent. Email/phone uniqueness
-- applies inside each portal only, never across all three tables.
CREATE TABLE customer_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext,
    normalized_phone varchar(32),
    password_hash varchar(255) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PENDING_VERIFICATION',
    email_verified_at timestamptz,
    phone_verified_at timestamptz,
    failed_login_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    security_version bigint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_customer_account_identifier CHECK (num_nonnulls(email, normalized_phone) >= 1),
    CONSTRAINT ck_customer_account_status CHECK (status IN ('PENDING_VERIFICATION', 'ACTIVE', 'LOCKED', 'DISABLED', 'CLOSED')),
    CONSTRAINT ck_customer_account_failed_logins CHECK (failed_login_attempts >= 0)
);
CREATE UNIQUE INDEX ux_customer_account_email ON customer_accounts(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX ux_customer_account_phone ON customer_accounts(normalized_phone) WHERE normalized_phone IS NOT NULL;

CREATE TABLE admin_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext,
    normalized_phone varchar(32),
    password_hash varchar(255) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    email_verified_at timestamptz,
    phone_verified_at timestamptz,
    failed_login_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    security_version bigint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 0,
    created_by_admin_account_id uuid REFERENCES admin_accounts(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_admin_account_identifier CHECK (num_nonnulls(email, normalized_phone) >= 1),
    CONSTRAINT ck_admin_account_status CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'CLOSED')),
    CONSTRAINT ck_admin_account_failed_logins CHECK (failed_login_attempts >= 0)
);
CREATE UNIQUE INDEX ux_admin_account_email ON admin_accounts(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX ux_admin_account_phone ON admin_accounts(normalized_phone) WHERE normalized_phone IS NOT NULL;

CREATE TABLE host_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext,
    normalized_phone varchar(32),
    password_hash varchar(255) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    email_verified_at timestamptz,
    phone_verified_at timestamptz,
    failed_login_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    security_version bigint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 0,
    created_by_admin_account_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_host_account_identifier CHECK (num_nonnulls(email, normalized_phone) >= 1),
    CONSTRAINT ck_host_account_status CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'CLOSED')),
    CONSTRAINT ck_host_account_failed_logins CHECK (failed_login_attempts >= 0)
);
CREATE UNIQUE INDEX ux_host_account_email ON host_accounts(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX ux_host_account_phone ON host_accounts(normalized_phone) WHERE normalized_phone IS NOT NULL;

-- Polymorphic account reference is validated by Authentication Service.
CREATE TABLE auth_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_type varchar(16) NOT NULL,
    account_id uuid NOT NULL,
    client_id varchar(100) NOT NULL,
    refresh_token_hash char(64) NOT NULL UNIQUE,
    token_family_id uuid NOT NULL DEFAULT gen_random_uuid(),
    device_id_hash char(64),
    device_name varchar(180),
    user_agent_hash char(64),
    first_ip inet,
    last_ip inet,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason varchar(500),
    CONSTRAINT ck_auth_session_account_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_auth_session_expiry CHECK (
        idle_expires_at > created_at
        AND absolute_expires_at >= idle_expires_at
        AND last_seen_at >= created_at
    ),
    CONSTRAINT ck_auth_session_revocation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX ix_auth_session_account_active ON auth_sessions(account_type, account_id, last_seen_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX ix_auth_session_family_active ON auth_sessions(token_family_id) WHERE revoked_at IS NULL;

CREATE TABLE account_action_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_type varchar(16) NOT NULL,
    account_id uuid NOT NULL,
    action_type varchar(32) NOT NULL,
    token_hash char(64) NOT NULL UNIQUE,
    destination_hash char(64),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    invalidated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_account_action_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_account_action_kind CHECK (action_type IN ('PASSWORD_RESET', 'EMAIL_VERIFICATION', 'PHONE_VERIFICATION')),
    CONSTRAINT ck_account_action_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_account_action_completion CHECK (num_nonnulls(used_at, invalidated_at) <= 1)
);
CREATE INDEX ix_account_action_pending ON account_action_tokens(account_type, account_id, action_type, expires_at) WHERE used_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE login_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_type varchar(16) NOT NULL,
    account_id uuid,
    login_identifier_hash char(64) NOT NULL,
    success boolean NOT NULL,
    failure_reason varchar(80),
    ip_address inet,
    user_agent_hash char(64),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_login_attempt_account_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_login_attempt_result CHECK ((success AND failure_reason IS NULL) OR NOT success)
);
CREATE INDEX ix_login_attempt_identifier ON login_attempts(account_type, login_identifier_hash, occurred_at DESC);
CREATE INDEX ix_login_attempt_ip ON login_attempts(ip_address, occurred_at DESC);

CREATE TABLE security_audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_type varchar(16),
    account_id uuid,
    session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
    event_type varchar(100) NOT NULL,
    success boolean NOT NULL,
    ip_address inet,
    user_agent_hash char(64),
    correlation_id varchar(100),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_security_audit_account_type CHECK (account_type IS NULL OR account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_security_audit_account_pair CHECK ((account_type IS NULL) = (account_id IS NULL)),
    CONSTRAINT ck_security_audit_details CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX ix_security_audit_account ON security_audit_events(account_type, account_id, occurred_at DESC);
CREATE INDEX ix_security_audit_event ON security_audit_events(event_type, occurred_at DESC);

CREATE TABLE processed_events (
    event_id uuid NOT NULL,
    consumer_name varchar(120) NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, consumer_name)
);

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type varchar(100) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    event_type varchar(160) NOT NULL,
    event_version integer NOT NULL DEFAULT 1 CHECK (event_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    correlation_id varchar(100),
    causation_id varchar(100),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    last_error text
);
CREATE INDEX ix_auth_outbox_pending ON outbox_events(available_at, occurred_at) WHERE published_at IS NULL;
