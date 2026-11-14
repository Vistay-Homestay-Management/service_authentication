SET search_path TO app, extensions, public;

ALTER TABLE identity_accounts DROP CONSTRAINT ck_identity_account_status;
ALTER TABLE identity_accounts ADD CONSTRAINT ck_identity_account_status
    CHECK (status IN ('PENDING_PROFILE', 'ACTIVE', 'LOCKED', 'DISABLED', 'CLOSED'));

ALTER TABLE identity_accounts ADD COLUMN profile_link_deadline timestamptz;
ALTER TABLE identity_accounts ADD COLUMN profile_id uuid;
ALTER TABLE identity_accounts ADD COLUMN linked_at timestamptz;

CREATE INDEX ix_identity_account_pending_profile
    ON identity_accounts(profile_link_deadline, created_at)
    WHERE status = 'PENDING_PROFILE';

COMMENT ON COLUMN identity_accounts.profile_link_deadline IS
    'Deadline after which privileged HOST/ADMIN accounts without a linked profile are disabled and removed from Keycloak.';
