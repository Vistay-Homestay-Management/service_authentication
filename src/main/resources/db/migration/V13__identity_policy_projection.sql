SET search_path TO app, extensions, public;

CREATE TABLE identity_policy_projection (
    account_type varchar(16) PRIMARY KEY,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    registration_enabled boolean NOT NULL,
    link_mode varchar(24) NOT NULL,
    source_event_id uuid NOT NULL UNIQUE,
    projected_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_identity_policy_projection_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_identity_policy_projection_link_mode CHECK (link_mode IN ('AUTO_LINK', 'REQUIRE_APPROVAL'))
);

COMMENT ON TABLE identity_policy_projection IS
    'Authentication projection of User-owned registration/link policy; Keycloak realm settings are reconciled from this monotonic version.';
