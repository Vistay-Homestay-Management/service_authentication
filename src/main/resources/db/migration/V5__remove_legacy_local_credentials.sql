SET search_path TO app, extensions, public;

-- Keycloak owns passwords, interactive sessions, verification actions and
-- login-attempt protection. Authentication retains only the identity
-- projection, provisioning idempotency/bootstrap state and its outbox.
DROP TABLE IF EXISTS security_audit_events;
DROP TABLE IF EXISTS account_action_tokens;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS customer_accounts;
DROP TABLE IF EXISTS host_accounts;
DROP TABLE IF EXISTS admin_accounts;
DROP TABLE IF EXISTS processed_events;

COMMENT ON TABLE identity_accounts IS
    'Minimal Keycloak identity projection; credentials and sessions are owned exclusively by Keycloak.';
