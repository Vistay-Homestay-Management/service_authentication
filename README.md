# ViStay Authentication Service

Keycloak-backed identity projection and controlled Backoffice account provisioning.

This repository is part of the ViStay Homestay Management platform. Epic 1 establishes a buildable, testable application shell and platform integrations; domain workflows are delivered by their owning epics.

## Backoffice account provisioning

`POST /api/v1/backoffice/accounts` requires a Backoffice bearer token whose
authorization snapshot contains `account:provision@ALL`. The request must also
include an `Idempotency-Key`; `X-Correlation-Id` is optional and defaults to a
generated UUID.

```json
{
  "email": "operator@vistay.vn",
  "fullName": "ViStay Operator",
  "temporaryPassword": "change-this-password",
  "reason": "Required for night operations"
}
```

The account is enabled in Keycloak with mandatory `UPDATE_PASSWORD`, then the
service records immutable actor/reason/correlation evidence and publishes
`vistay.auth.account-provisioned.v1`. `service_user` consumes that fact to
create the profile and authorization subject. Replaying the same key and body
returns the original account; reusing an email with a different key returns
HTTP 409. Passwords and tokens are never stored in this service database.

The one-time `/api/v1/backoffice/accounts/bootstrap` route uses
`X-ViStay-Bootstrap-Token` instead of a bearer token and is permanently closed
after the initial account succeeds.
