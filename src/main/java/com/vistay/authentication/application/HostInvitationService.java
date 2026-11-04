package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.HostActivationState;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.HostIdentity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Service
public class HostInvitationService {
    public static final String HOST_INVITATION_ISSUED = "vistay.host.invitation-issued";
    public static final String HOST_IDENTITY_ACTIVATED = "vistay.host.identity-activated";

    private static final String HOST_REALM = "vistay-host";
    private static final String HOST_SUBJECT_TYPE = "HOST";
    private static final String OWNERSHIP_TERM = "OWNED";
    private static final List<String> ACTIONS = List.of("VERIFY_EMAIL", "UPDATE_PASSWORD");

    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final ObjectMapper json;
    private final TransactionTemplate transactions;
    private final Duration invitationTtl;

    @Autowired
    public HostInvitationService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        TransactionTemplate transactions,
        @Value("${vistay.host-invitation.ttl:PT24H}") Duration invitationTtl
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.json = json;
        this.transactions = transactions;
        this.invitationTtl = invitationTtl;
    }

    public HostInvitationService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        TransactionTemplate transactions
    ) {
        this(jdbc, keycloak, json, transactions, Duration.ofHours(24));
    }

    public HostInvitation invite(
        String idempotencyKey,
        UUID actorAccountId,
        String email,
        String displayName,
        String phone,
        String reason,
        String accountType,
        UUID propertyId,
        UUID branchId,
        String correlationId
    ) {
        var key = requireIdempotencyKey(idempotencyKey);
        var actor = requireActor(actorAccountId);
        var normalizedEmail = normalizeEmail(email);
        var normalizedName = normalizeDisplayName(displayName);
        var normalizedPhone = normalizePhone(phone);
        var normalizedReason = requireReason(reason);
        requireHostType(accountType);
        var property = requirePartition(propertyId, branchId);
        var correlation = normalizeCorrelationId(correlationId);
        var requestHash = requestHash(
            normalizedEmail, normalizedName, normalizedPhone, normalizedReason,
            property.propertyId(), property.branchId()
        );

        var previous = findByIdempotencyKey(key);
        if (previous != null) {
            verifyRequestHash(previous.requestHash(), requestHash);
            return dispatchPendingEmail(previous, true);
        }

        if (findByEmail(normalizedEmail) != null) {
            throw error(HttpStatus.CONFLICT, "HOST_EMAIL_ALREADY_INVITED");
        }

        var invitationId = deterministicInvitationId(key);
        var accountId = deterministicAccountId(invitationId);
        HostIdentity identity;
        try {
            identity = keycloak.ensureHostUser(
                normalizedEmail, normalizedName, normalizedPhone, invitationId
            );
        } catch (KeycloakAdminClient.HostSubjectCollisionException collision) {
            throw error(HttpStatus.CONFLICT, "HOST_SUBJECT_COLLISION");
        } catch (RestClientException unavailable) {
            throw identityProviderUnavailable(unavailable);
        }

        var expiresAt = now().plus(invitationTtl);
        try {
            persistInvitation(
                invitationId, accountId, identity.subject(), key, requestHash,
                normalizedEmail, normalizedName, normalizedPhone, normalizedReason,
                property.propertyId(), property.branchId(), actor, correlation, expiresAt
            );
        } catch (DataIntegrityViolationException concurrent) {
            var winner = findByIdempotencyKey(key);
            if (winner != null) {
                verifyRequestHash(winner.requestHash(), requestHash);
                return dispatchPendingEmail(winner, true);
            }
            if (findByEmail(normalizedEmail) != null) {
                throw error(HttpStatus.CONFLICT, "HOST_EMAIL_ALREADY_INVITED");
            }
            throw concurrent;
        }

        return dispatchPendingEmail(requireInvitation(invitationId), false);
    }

    public HostInvitation resend(
        String idempotencyKey,
        UUID actorAccountId,
        UUID invitationId,
        String reason,
        String correlationId
    ) {
        var key = requireIdempotencyKey(idempotencyKey);
        var actor = requireActor(actorAccountId);
        var normalizedReason = requireReason(reason);
        var correlation = normalizeCorrelationId(correlationId);
        var invitation = requireInvitation(invitationId);
        requireResendable(invitation);
        if (!now().isBefore(invitation.expiresAt())) {
            expire(invitation, correlation);
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_EXPIRED");
        }
        var requestHash = sha256(String.join("\n", "resend-v1", invitationId.toString(), normalizedReason));

        var previous = findResend(key);
        if (previous != null) {
            verifyRequestHash(previous.requestHash(), requestHash);
            if ("COMPLETED".equals(previous.status())) {
                return view(invitation, true);
            }
            if ("PENDING".equals(previous.status())) {
                throw error(HttpStatus.CONFLICT, "HOST_INVITATION_RESEND_IN_PROGRESS");
            }
        } else {
            var inserted = jdbc.sql("""
                INSERT INTO host_invitation_resends(
                    idempotency_key, request_hash, invitation_id, actor_account_id,
                    reason, correlation_id
                ) VALUES (:key, :hash, :invitation, :actor, :reason, :correlation)
                ON CONFLICT DO NOTHING
                """)
                .param("key", key).param("hash", requestHash).param("invitation", invitationId)
                .param("actor", actor).param("reason", normalizedReason)
                .param("correlation", correlation).update() == 1;
            if (!inserted) {
                var concurrent = requireResend(key);
                verifyRequestHash(concurrent.requestHash(), requestHash);
                if ("COMPLETED".equals(concurrent.status())) {
                    return view(requireInvitation(invitationId), true);
                }
                if ("PENDING".equals(concurrent.status())) {
                    throw error(HttpStatus.CONFLICT, "HOST_INVITATION_RESEND_IN_PROGRESS");
                }
            }
        }

        try {
            keycloak.sendHostActivationEmail(invitation.keycloakSubject());
        } catch (RestClientException unavailable) {
            markResendRetryRequired(key, invitation, actor, correlation, normalizedReason);
            throw identityProviderUnavailable(unavailable, "HOST_INVITATION_DISPATCH_UNAVAILABLE");
        }

        var completed = transactions.execute(status -> {
            var locked = lockInvitation(invitationId);
            requireResendable(locked);
            var nextVersion = locked.version() + 1;
            jdbc.sql("""
                UPDATE host_invitations
                SET state = 'ACTIONS_PENDING', action_dispatch_status = 'SENT',
                    version = :version, updated_at = now()
                WHERE invitation_id = :id
                """)
                .param("version", nextVersion).param("id", invitationId).update();
            audit(invitationId, actor, "INVITATION_RESENT", locked.state(),
                "ACTIONS_PENDING", normalizedReason, correlation);
            jdbc.sql("""
                UPDATE host_invitation_resends
                SET status = 'COMPLETED', completed_at = now()
                WHERE idempotency_key = :key
                """).param("key", key).update();
            return requireInvitation(invitationId);
        });
        return view(completed, false);
    }

    public HostAccount activate(
        UUID invitationId,
        String hostSubject,
        long expectedVersion,
        String correlationId
    ) {
        var correlation = normalizeCorrelationId(correlationId);
        var invitation = requireInvitation(invitationId);
        if (!invitation.keycloakSubject().equals(hostSubject)) {
            throw error(HttpStatus.FORBIDDEN, "HOST_WRONG_REALM_OR_TYPE");
        }
        if ("ACTIVE".equals(invitation.state())) {
            return accountView(invitation, true);
        }
        if (invitation.version() != expectedVersion) {
            throw error(HttpStatus.CONFLICT, "HOST_STALE_VERSION");
        }
        if (!now().isBefore(invitation.expiresAt())) {
            expire(invitation, correlation);
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_EXPIRED");
        }

        HostActivationState state;
        try {
            state = keycloak.hostActivationState(hostSubject);
        } catch (RestClientException unavailable) {
            throw identityProviderUnavailable(unavailable);
        }
        if (!state.enabled() || !state.emailVerified() || !state.requiredActions().isEmpty()) {
            throw error(HttpStatus.CONFLICT, "HOST_ACTIVATION_ACTIONS_PENDING");
        }

        var result = transactions.execute(status -> {
            var locked = lockInvitation(invitationId);
            if ("ACTIVE".equals(locked.state())) {
                return accountView(locked, true);
            }
            if (locked.version() != expectedVersion) {
                throw error(HttpStatus.CONFLICT, "HOST_STALE_VERSION");
            }
            if (!now().isBefore(locked.expiresAt())) {
                expireLocked(locked, correlation);
                throw error(HttpStatus.CONFLICT, "HOST_INVITATION_EXPIRED");
            }

            var accountVersion = jdbc.sql("""
                UPDATE identity_accounts
                SET status = 'ACTIVE', version = version + 1, updated_at = now()
                WHERE id = :id AND status <> 'ACTIVE'
                RETURNING version
                """)
                .param("id", locked.accountId())
                .query(Long.class)
                .optional()
                .orElseGet(() -> jdbc.sql("""
                    SELECT version FROM identity_accounts WHERE id = :id
                    """).param("id", locked.accountId()).query(Long.class).single());
            var aggregateVersion = locked.version() + 1;
            var activatedAt = now();
            jdbc.sql("""
                UPDATE host_invitations
                SET state = 'ACTIVE', version = :version, activated_at = :activatedAt,
                    updated_at = now()
                WHERE invitation_id = :id
                """)
                .param("version", aggregateVersion).param("activatedAt", activatedAt)
                .param("id", invitationId).update();
            audit(invitationId, null, "INVITATION_ACTIVATED", locked.state(), "ACTIVE",
                "Keycloak email verification and required actions completed", correlation);
            emit(HOST_IDENTITY_ACTIVATED, invitationId, aggregateVersion, correlation, Map.of(
                "invitationId", invitationId,
                "accountId", locked.accountId(),
                "realm", HOST_SUBJECT_TYPE,
                "subjectType", HOST_SUBJECT_TYPE,
                "state", "ACTIVE",
                "authorizationVersion", accountVersion,
                "activationSource", "KEYCLOAK",
                "aggregateVersion", aggregateVersion,
                "activatedAt", activatedAt
            ));
            return new HostAccount(
                locked.accountId(), HOST_SUBJECT_TYPE, HOST_SUBJECT_TYPE,
                "ACTIVE", accountVersion, aggregateVersion, false
            );
        });
        return result;
    }

    private HostInvitation dispatchPendingEmail(HostInvitationRow invitation, boolean replayed) {
        if ("EXPIRED".equals(invitation.state())) {
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_EXPIRED");
        }
        if ("CANCELLED".equals(invitation.state())) {
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_NOT_RESENDABLE");
        }
        if (!"ACTIVE".equals(invitation.state()) && !now().isBefore(invitation.expiresAt())) {
            expire(invitation, invitation.correlationId());
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_EXPIRED");
        }
        if ("SENT".equals(invitation.actionDispatchStatus())) {
            return view(invitation, replayed);
        }
        try {
            keycloak.sendHostActivationEmail(invitation.keycloakSubject());
        } catch (RestClientException unavailable) {
            markDispatchRetryRequired(invitation, unavailable);
            throw identityProviderUnavailable(unavailable, "HOST_INVITATION_DISPATCH_UNAVAILABLE");
        }

        var sent = transactions.execute(status -> {
            var locked = lockInvitation(invitation.invitationId());
            if ("SENT".equals(locked.actionDispatchStatus())) {
                return locked;
            }
            var nextVersion = locked.version() + 1;
            jdbc.sql("""
                UPDATE host_invitations
                SET state = 'ACTIONS_PENDING', action_dispatch_status = 'SENT',
                    version = :version, updated_at = now()
                WHERE invitation_id = :id
                """)
                .param("version", nextVersion).param("id", locked.invitationId()).update();
            audit(locked.invitationId(), locked.actorAccountId(), "ACTIVATION_EMAIL_DISPATCHED",
                locked.state(), "ACTIONS_PENDING", "Keycloak execute-actions email dispatched", locked.correlationId());
            return requireInvitation(locked.invitationId());
        });
        return view(sent, replayed);
    }

    private void persistInvitation(
        UUID invitationId,
        UUID accountId,
        String keycloakSubject,
        String idempotencyKey,
        String requestHash,
        String email,
        String displayName,
        String phone,
        String reason,
        UUID propertyId,
        UUID branchId,
        UUID actorAccountId,
        UUID correlationId,
        OffsetDateTime expiresAt
    ) {
        jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, :realm, :subject, 'HOST', :email, 'DISABLED')
            ON CONFLICT (id) DO NOTHING
            """)
            .param("id", accountId).param("realm", HOST_REALM).param("subject", keycloakSubject)
            .param("email", email).update();

        var inserted = jdbc.sql("""
            INSERT INTO host_invitations(
                invitation_id, account_id, keycloak_subject, email, display_name, phone,
                request_hash, idempotency_key, expires_at, actor_account_id, reason,
                property_id, branch_id, correlation_id
            ) VALUES (
                :invitation, :account, :subject, :email, :displayName, :phone,
                :requestHash, :idempotencyKey, :expiresAt, :actor, :reason,
                :propertyId, :branchId, :correlation
            )
            ON CONFLICT DO NOTHING
            """)
            .param("invitation", invitationId).param("account", accountId)
            .param("subject", keycloakSubject).param("email", email)
            .param("displayName", displayName).param("phone", phone)
            .param("requestHash", requestHash).param("idempotencyKey", idempotencyKey)
            .param("expiresAt", expiresAt).param("actor", actorAccountId)
            .param("reason", reason).param("propertyId", propertyId).param("branchId", branchId)
            .param("correlation", correlationId).update();
        if (inserted == 0) {
            var existing = findByIdempotencyKey(idempotencyKey);
            if (existing == null) {
                throw error(HttpStatus.CONFLICT, "HOST_EMAIL_ALREADY_INVITED");
            }
            verifyRequestHash(existing.requestHash(), requestHash);
            return;
        }

        audit(invitationId, actorAccountId, "INVITATION_ISSUED", null, "INVITED", reason, correlationId);
        emit(HOST_INVITATION_ISSUED, invitationId, 1, correlationId, Map.ofEntries(
            Map.entry("invitationId", invitationId),
            Map.entry("realm", HOST_SUBJECT_TYPE),
            Map.entry("subjectType", HOST_SUBJECT_TYPE),
            Map.entry("state", "PENDING"),
            Map.entry("contactReferenceHash", contactReferenceHash(email)),
            Map.entry("propertyId", propertyId),
            Map.entry("branchId", branchId),
            Map.entry("ownershipTerm", OWNERSHIP_TERM),
            Map.entry("aggregateVersion", 1),
            Map.entry("issuedByType", "ADMIN"),
            Map.entry("issuedAt", now()),
            Map.entry("expiresAt", expiresAt)
        ));
    }

    private void emit(
        String eventType,
        UUID aggregateId,
        long aggregateVersion,
        UUID correlationId,
        Object payload
    ) {
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                'HostInvitation', :aggregateId, :aggregateVersion, :eventType,
                1, CAST(:payload AS jsonb), :correlationId
            )
            """)
            .param("aggregateId", aggregateId).param("aggregateVersion", aggregateVersion)
            .param("eventType", eventType).param("payload", writeJson(payload))
            .param("correlationId", correlationId.toString()).update();
    }

    private void audit(
        UUID invitationId,
        UUID actorAccountId,
        String action,
        String previousState,
        String resultingState,
        String reason,
        UUID correlationId
    ) {
        jdbc.sql("""
            INSERT INTO host_invitation_audit(
                invitation_id, actor_account_id, action, previous_state,
                resulting_state, reason, correlation_id
            ) VALUES (:invitation, :actor, :action, :previous, :resulting, :reason, :correlation)
            """)
            .param("invitation", invitationId).param("actor", actorAccountId)
            .param("action", action).param("previous", previousState)
            .param("resulting", resultingState).param("reason", reason)
            .param("correlation", correlationId).update();
    }

    private void markDispatchRetryRequired(HostInvitationRow invitation, RestClientException failure) {
        transactions.executeWithoutResult(status -> {
            var current = lockInvitation(invitation.invitationId());
            if ("SENT".equals(current.actionDispatchStatus())) {
                return;
            }
            jdbc.sql("""
                UPDATE host_invitations
                SET action_dispatch_status = 'RETRY_REQUIRED', updated_at = now()
                WHERE invitation_id = :id
                """).param("id", current.invitationId()).update();
            audit(current.invitationId(), current.actorAccountId(), "ACTIVATION_EMAIL_DISPATCH_FAILED",
                current.state(), current.state(), "Keycloak action email dispatch requires retry", current.correlationId());
        });
    }

    private void markResendRetryRequired(
        String key,
        HostInvitationRow invitation,
        UUID actor,
        UUID correlation,
        String reason
    ) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("""
                UPDATE host_invitation_resends
                SET status = 'RETRY_REQUIRED'
                WHERE idempotency_key = :key
                """).param("key", key).update();
            audit(invitation.invitationId(), actor, "INVITATION_RESEND_DISPATCH_FAILED",
                invitation.state(), invitation.state(), reason, correlation);
        });
    }

    private void expire(HostInvitationRow invitation, UUID correlation) {
        transactions.executeWithoutResult(status -> expireLocked(lockInvitation(invitation.invitationId()), correlation));
    }

    private void expireLocked(HostInvitationRow invitation, UUID correlation) {
        if ("EXPIRED".equals(invitation.state()) || "ACTIVE".equals(invitation.state())) {
            return;
        }
        jdbc.sql("""
            UPDATE host_invitations
            SET state = 'EXPIRED', version = version + 1, updated_at = now()
            WHERE invitation_id = :id
            """).param("id", invitation.invitationId()).update();
        audit(invitation.invitationId(), invitation.actorAccountId(), "INVITATION_EXPIRED",
            invitation.state(), "EXPIRED", "Invitation expiry reached", correlation);
    }

    private HostInvitationRow lockInvitation(UUID invitationId) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, realm, subject_type, keycloak_subject,
                   state, action_dispatch_status, expires_at, actor_account_id,
                   correlation_id, version, activated_at, request_hash
            FROM host_invitations WHERE invitation_id = :id FOR UPDATE
            """)
            .param("id", invitationId).query(HostInvitationRow.class).optional()
            .orElseThrow(() -> error(HttpStatus.NOT_FOUND, "HOST_INVITATION_NOT_FOUND"));
    }

    private HostInvitationRow requireInvitation(UUID invitationId) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, realm, subject_type, keycloak_subject,
                   state, action_dispatch_status, expires_at, actor_account_id,
                   correlation_id, version, activated_at, request_hash
            FROM host_invitations WHERE invitation_id = :id
            """)
            .param("id", invitationId).query(HostInvitationRow.class).optional()
            .orElseThrow(() -> error(HttpStatus.NOT_FOUND, "HOST_INVITATION_NOT_FOUND"));
    }

    private HostInvitationRow findByIdempotencyKey(String key) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, realm, subject_type, keycloak_subject,
                   state, action_dispatch_status, expires_at, actor_account_id,
                   correlation_id, version, activated_at, request_hash
            FROM host_invitations WHERE idempotency_key = :key
            """)
            .param("key", key).query(HostInvitationRow.class).optional().orElse(null);
    }

    private HostInvitationRow findByEmail(String email) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, realm, subject_type, keycloak_subject,
                   state, action_dispatch_status, expires_at, actor_account_id,
                   correlation_id, version, activated_at, request_hash
            FROM host_invitations WHERE realm = :realm AND email = :email
            """)
            .param("realm", HOST_REALM).param("email", email)
            .query(HostInvitationRow.class).optional().orElse(null);
    }

    private HostResendRow findResend(String key) {
        return jdbc.sql("""
            SELECT idempotency_key, request_hash, invitation_id, status
            FROM host_invitation_resends WHERE idempotency_key = :key
            """)
            .param("key", key).query(HostResendRow.class).optional().orElse(null);
    }

    private HostResendRow requireResend(String key) {
        var row = findResend(key);
        if (row == null) {
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_RESEND_IN_PROGRESS");
        }
        return row;
    }

    private static void requireResendable(HostInvitationRow invitation) {
        if ("ACTIVE".equals(invitation.state())) {
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_ALREADY_ACTIVE");
        }
        if ("EXPIRED".equals(invitation.state()) || "CANCELLED".equals(invitation.state())) {
            throw error(HttpStatus.CONFLICT, "HOST_INVITATION_NOT_RESENDABLE");
        }
    }

    private HostAccount accountView(HostInvitationRow invitation, boolean replayed) {
        var version = jdbc.sql("SELECT version FROM identity_accounts WHERE id = :id")
            .param("id", invitation.accountId()).query(Long.class).single();
        return new HostAccount(
            invitation.accountId(), HOST_SUBJECT_TYPE, invitation.subjectType(),
            invitation.state(), version, invitation.version(), replayed
        );
    }

    private static HostInvitation view(HostInvitationRow row, boolean replayed) {
        return new HostInvitation(
            row.invitationId(), row.accountId(), row.realm(), row.subjectType(),
            row.state(), row.version(), row.expiresAt(), replayed
        );
    }

    private static UUID requireActor(UUID actor) {
        if (actor == null) {
            throw error(HttpStatus.UNAUTHORIZED, "HOST_ACTOR_REQUIRED");
        }
        return actor;
    }

    private static String requireIdempotencyKey(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) {
            throw error(HttpStatus.BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY");
        }
        return normalized;
    }

    private static String normalizeEmail(String value) {
        var normalized = value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
        if (normalized.isEmpty() || !normalized.contains("@") || normalized.length() > 320) {
            throw error(HttpStatus.UNPROCESSABLE_ENTITY, "HOST_INVALID_EMAIL");
        }
        return normalized;
    }

    private static String normalizeDisplayName(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 180) {
            throw error(HttpStatus.UNPROCESSABLE_ENTITY, "HOST_INVALID_DISPLAY_NAME");
        }
        return normalized;
    }

    private static String normalizePhone(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        var normalized = value.trim();
        if (normalized.length() < 3 || normalized.length() > 40) {
            throw error(HttpStatus.UNPROCESSABLE_ENTITY, "HOST_INVALID_PHONE");
        }
        return normalized;
    }

    private static String requireReason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) {
            throw error(HttpStatus.BAD_REQUEST, "HOST_INVALID_REASON");
        }
        return normalized;
    }

    private static void requireHostType(String accountType) {
        if (accountType != null && !HOST_SUBJECT_TYPE.equalsIgnoreCase(accountType.trim())) {
            throw error(HttpStatus.UNPROCESSABLE_ENTITY, "HOST_WRONG_REALM_OR_TYPE");
        }
    }

    private static Partition requirePartition(UUID propertyId, UUID branchId) {
        if (propertyId == null || branchId == null) {
            throw error(HttpStatus.FORBIDDEN, "HOST_PARTITION_REQUIRED");
        }
        return new Partition(propertyId, branchId);
    }

    private static UUID normalizeCorrelationId(String value) {
        if (value == null || value.isBlank()) {
            return UUID.randomUUID();
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException invalid) {
            throw error(HttpStatus.BAD_REQUEST, "HOST_INVALID_CORRELATION_ID");
        }
    }

    private static UUID deterministicInvitationId(String idempotencyKey) {
        return UUID.nameUUIDFromBytes(("vistay:host-invitation:" + idempotencyKey)
            .getBytes(StandardCharsets.UTF_8));
    }

    private static UUID deterministicAccountId(UUID invitationId) {
        return UUID.nameUUIDFromBytes(("vistay:host-account:" + invitationId)
            .getBytes(StandardCharsets.UTF_8));
    }

    private static String requestHash(
        String email,
        String displayName,
        String phone,
        String reason,
        UUID propertyId,
        UUID branchId
    ) {
        return sha256(String.join("\n", "host-invitation-v1", HOST_SUBJECT_TYPE,
            email, displayName, phone == null ? "" : phone, reason,
            propertyId.toString(), branchId.toString()));
    }

    private static String contactReferenceHash(String email) {
        return "sha256:" + sha256(email);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static OffsetDateTime now() {
        return OffsetDateTime.now(ZoneOffset.UTC);
    }

    private static void verifyRequestHash(String persisted, String expected) {
        if (persisted == null || !MessageDigest.isEqual(
            persisted.getBytes(StandardCharsets.US_ASCII), expected.getBytes(StandardCharsets.US_ASCII)
        )) {
            throw error(HttpStatus.CONFLICT, "HOST_IDEMPOTENCY_CONFLICT");
        }
    }

    private static String writeJson(ObjectMapper json, Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize Host identity event", failure);
        }
    }

    private String writeJson(Object value) {
        return writeJson(json, value);
    }

    private static ResponseStatusException error(HttpStatus status, String code) {
        return new ResponseStatusException(status, code);
    }

    private static ResponseStatusException identityProviderUnavailable(RestClientException failure) {
        return identityProviderUnavailable(failure, "IDENTITY_PROVIDER_UNAVAILABLE");
    }

    private static ResponseStatusException identityProviderUnavailable(
        RestClientException failure,
        String code
    ) {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, code, failure);
    }

    public record HostInvitation(
        UUID invitationId,
        UUID accountId,
        String realm,
        String subjectType,
        String state,
        long aggregateVersion,
        OffsetDateTime expiresAt,
        boolean replayed
    ) {}

    public record HostAccount(
        UUID accountId,
        String realm,
        String subjectType,
        String state,
        long authorizationVersion,
        long aggregateVersion,
        boolean replayed
    ) {}

    private record Partition(UUID propertyId, UUID branchId) {}
    private record HostResendRow(String idempotencyKey, String requestHash, UUID invitationId, String status) {}
    private record HostInvitationRow(
        UUID invitationId,
        UUID accountId,
        String realm,
        String subjectType,
        String keycloakSubject,
        String state,
        String actionDispatchStatus,
        OffsetDateTime expiresAt,
        UUID actorAccountId,
        UUID correlationId,
        long version,
        OffsetDateTime activatedAt,
        String requestHash
    ) {}
}
