SET search_path TO app, extensions, public;

ALTER TABLE provisioning_requests
    ADD COLUMN request_hash_version smallint NOT NULL DEFAULT 1,
    ADD COLUMN actor_account_id uuid,
    ADD COLUMN reason varchar(500) NOT NULL DEFAULT 'Migrated legacy provisioning record',
    ADD COLUMN correlation_id uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN provisioning_mode varchar(16) NOT NULL DEFAULT 'LEGACY';

ALTER TABLE provisioning_requests
    ALTER COLUMN request_hash_version DROP DEFAULT,
    ALTER COLUMN reason DROP DEFAULT,
    ALTER COLUMN correlation_id DROP DEFAULT,
    ALTER COLUMN provisioning_mode DROP DEFAULT,
    ADD CONSTRAINT ck_provisioning_request_hash_version
        CHECK (request_hash_version IN (1, 2)),
    ADD CONSTRAINT ck_provisioning_mode
        CHECK (provisioning_mode IN ('LEGACY', 'BOOTSTRAP', 'STANDARD')),
    ADD CONSTRAINT fk_provisioning_actor
        FOREIGN KEY (actor_account_id) REFERENCES identity_accounts(id),
    ADD CONSTRAINT ck_provisioning_actor
        CHECK (
            (provisioning_mode = 'STANDARD' AND actor_account_id IS NOT NULL)
            OR (provisioning_mode <> 'STANDARD' AND actor_account_id IS NULL)
        );

CREATE INDEX ix_provisioning_request_actor
    ON provisioning_requests(actor_account_id, created_at DESC)
    WHERE actor_account_id IS NOT NULL;

COMMENT ON TABLE provisioning_requests IS
    'Idempotency and immutable audit ledger for Backoffice account provisioning; credentials remain in Keycloak.';
