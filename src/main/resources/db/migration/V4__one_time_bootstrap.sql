SET search_path TO app, extensions, public;

ALTER TABLE provisioning_requests ALTER COLUMN idempotency_key TYPE varchar(160);

CREATE TABLE authentication_bootstrap_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    reservation_key varchar(160),
    identity_account_id uuid REFERENCES identity_accounts(id) ON DELETE RESTRICT,
    completed_at timestamptz,
    CONSTRAINT ck_authentication_bootstrap_complete CHECK (
        (completed_at IS NULL AND identity_account_id IS NULL)
        OR (completed_at IS NOT NULL AND identity_account_id IS NOT NULL)
    )
);

INSERT INTO authentication_bootstrap_state(singleton, identity_account_id, completed_at)
VALUES (
    true,
    (SELECT id FROM identity_accounts WHERE account_type = 'ADMIN' ORDER BY created_at LIMIT 1),
    CASE WHEN EXISTS (SELECT 1 FROM identity_accounts WHERE account_type = 'ADMIN') THEN now() ELSE NULL END
);
