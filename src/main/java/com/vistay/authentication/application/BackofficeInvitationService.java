package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Locale;
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
public class BackofficeInvitationService {
    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final ObjectMapper json;
    private final TransactionTemplate transactions;
    private final Duration invitationTtl;

    @Autowired
    public BackofficeInvitationService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        TransactionTemplate transactions,
        @Value("${vistay.backoffice-invitation.ttl:PT24H}") Duration invitationTtl
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.json = json;
        this.transactions = transactions;
        this.invitationTtl = invitationTtl;
    }

    public BackofficeInvitationService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        TransactionTemplate transactions
    ) {
        this(jdbc, keycloak, json, transactions, Duration.ofHours(24));
    }

    public InvitedAccount invite(
        String idempotencyKey,
        UUID actorAccountId,
        String email,
        String fullName,
        String reason,
        String correlationId
    ) {
        var key = requireIdempotencyKey(idempotencyKey);
        if (actorAccountId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
        var normalizedEmail = normalizeEmail(email);
        var normalizedName = normalizeName(fullName);
        var normalizedReason = normalizeReason(reason);
        var correlation = normalizeCorrelationId(correlationId);
        var requestHash = sha256(String.join("\n", "backoffice-invitation-v1",
            normalizedEmail, normalizedName, normalizedReason));

        var previous = findByIdempotencyKey(key);
        if (previous != null) {
            verifyRequestHash(previous.requestHash(), requestHash);
            return dispatch(previous, true);
        }
        if (findAccountByEmail(normalizedEmail)) {
            throw error(HttpStatus.CONFLICT, "BACKOFFICE_ACCOUNT_ALREADY_EXISTS");
        }

        var invitationId = UUID.nameUUIDFromBytes(
            ("vistay:backoffice-invitation:" + key).getBytes(StandardCharsets.UTF_8)
        );
        String subject;
        try {
            subject = keycloak.ensureBackofficeInvitedUser(
                normalizedEmail, normalizedName, invitationId
            );
        } catch (KeycloakAdminClient.BackofficeSubjectCollisionException collision) {
            throw error(HttpStatus.CONFLICT, "BACKOFFICE_ACCOUNT_ALREADY_EXISTS");
        } catch (RestClientException unavailable) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE, "IDENTITY_PROVIDER_UNAVAILABLE", unavailable
            );
        }
        var accountId = keycloakSubject(subject);
        var expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plus(invitationTtl);

        try {
            transactions.executeWithoutResult(status -> persist(
                invitationId, accountId, subject, key, requestHash, normalizedEmail,
                normalizedName, normalizedReason, actorAccountId, correlation, expiresAt
            ));
        } catch (DataIntegrityViolationException concurrent) {
            var winner = findByIdempotencyKey(key);
            if (winner != null) {
                verifyRequestHash(winner.requestHash(), requestHash);
                return dispatch(winner, true);
            }
            throw error(HttpStatus.CONFLICT, "BACKOFFICE_ACCOUNT_ALREADY_EXISTS");
        }
        return dispatch(requireInvitation(invitationId), false);
    }

    private void persist(
        UUID invitationId,
        UUID accountId,
        String subject,
        String idempotencyKey,
        String requestHash,
        String email,
        String fullName,
        String reason,
        UUID actorAccountId,
        UUID correlationId,
        OffsetDateTime expiresAt
    ) {
        var inserted = jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, 'vistay-backoffice', :subject, 'ADMIN', :email, 'ACTIVE')
            ON CONFLICT DO NOTHING
            """)
            .param("id", accountId).param("subject", subject).param("email", email).update();
        if (inserted != 1) {
            throw error(HttpStatus.CONFLICT, "BACKOFFICE_ACCOUNT_ALREADY_EXISTS");
        }

        jdbc.sql("""
            INSERT INTO backoffice_account_invitations(
                invitation_id, account_id, keycloak_subject, email, display_name,
                request_hash, idempotency_key, expires_at, actor_account_id,
                reason, correlation_id
            ) VALUES (
                :invitationId, :accountId, :subject, :email, :displayName,
                :requestHash, :idempotencyKey, :expiresAt, :actorAccountId,
                :reason, :correlationId
            )
            """)
            .param("invitationId", invitationId).param("accountId", accountId)
            .param("subject", subject).param("email", email).param("displayName", fullName)
            .param("requestHash", requestHash).param("idempotencyKey", idempotencyKey)
            .param("expiresAt", expiresAt).param("actorAccountId", actorAccountId)
            .param("reason", reason).param("correlationId", correlationId).update();

        var payload = writeJson(new AccountProvisionedData(
            accountId, "BACKOFFICE", email, fullName, "INVITATION",
            OffsetDateTime.now(ZoneOffset.UTC)
        ));
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                'IdentityAccount', :aggregateId, 1, :eventType,
                1, CAST(:payload AS jsonb), :correlationId
            )
            """)
            .param("aggregateId", accountId)
            .param("eventType", AuthService.BACKOFFICE_ACCOUNT_PROVISIONED)
            .param("payload", payload).param("correlationId", correlationId.toString()).update();
    }

    private InvitedAccount dispatch(InvitationRow invitation, boolean replayed) {
        var outcome = transactions.execute(status -> dispatchLocked(
            invitation.invitationId(), replayed
        ));
        if (outcome == null) {
            throw new IllegalStateException("Employee invitation dispatch returned no outcome");
        }
        if (outcome.failure() != null) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "BACKOFFICE_INVITATION_DISPATCH_UNAVAILABLE",
                outcome.failure()
            );
        }
        return outcome.account();
    }

    private DispatchOutcome dispatchLocked(UUID invitationId, boolean replayed) {
        var invitation = requireInvitationForUpdate(invitationId);
        if ("SENT".equals(invitation.actionDispatchStatus())) {
            return DispatchOutcome.sent(view(invitation, replayed));
        }
        if (!OffsetDateTime.now(ZoneOffset.UTC).isBefore(invitation.expiresAt())) {
            throw error(HttpStatus.CONFLICT, "BACKOFFICE_INVITATION_EXPIRED");
        }
        try {
            keycloak.sendBackofficeActivationEmail(invitation.keycloakSubject());
        } catch (RestClientException unavailable) {
            jdbc.sql("""
                UPDATE backoffice_account_invitations
                SET action_dispatch_status = 'RETRY_REQUIRED', updated_at = now()
                WHERE invitation_id = :id AND action_dispatch_status <> 'SENT'
                """).param("id", invitation.invitationId()).update();
            return DispatchOutcome.failed(unavailable);
        }
        jdbc.sql("""
            UPDATE backoffice_account_invitations
            SET action_dispatch_status = 'SENT', action_dispatched_at = now(), updated_at = now()
            WHERE invitation_id = :id AND action_dispatch_status <> 'SENT'
            """).param("id", invitation.invitationId()).update();
        return DispatchOutcome.sent(view(requireInvitation(invitation.invitationId()), replayed));
    }

    private InvitationRow findByIdempotencyKey(String key) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, keycloak_subject, email, display_name,
                   request_hash, action_dispatch_status, expires_at, created_at
            FROM backoffice_account_invitations WHERE idempotency_key = :key
            """).param("key", key).query(InvitationRow.class).optional().orElse(null);
    }

    private InvitationRow requireInvitation(UUID invitationId) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, keycloak_subject, email, display_name,
                   request_hash, action_dispatch_status, expires_at, created_at
            FROM backoffice_account_invitations WHERE invitation_id = :id
            """).param("id", invitationId).query(InvitationRow.class).single();
    }

    private InvitationRow requireInvitationForUpdate(UUID invitationId) {
        return jdbc.sql("""
            SELECT invitation_id, account_id, keycloak_subject, email, display_name,
                   request_hash, action_dispatch_status, expires_at, created_at
            FROM backoffice_account_invitations
            WHERE invitation_id = :id
            FOR UPDATE
            """).param("id", invitationId).query(InvitationRow.class).single();
    }

    private boolean findAccountByEmail(String email) {
        return jdbc.sql("""
            SELECT count(*) FROM identity_accounts
            WHERE realm = 'vistay-backoffice' AND email = :email
            """).param("email", email).query(Long.class).single() > 0;
    }

    private static InvitedAccount view(InvitationRow row, boolean replayed) {
        return new InvitedAccount(
            row.invitationId(), row.accountId(), row.email(), row.displayName(),
            row.actionDispatchStatus(), row.expiresAt(), row.createdAt(), replayed
        );
    }

    private String writeJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize employee invitation event", failure);
        }
    }

    private static String requireIdempotencyKey(String value) {
        if (value == null || value.isBlank() || value.trim().length() > 160) {
            throw error(HttpStatus.BAD_REQUEST,
                "Idempotency-Key is required and must not exceed 160 characters");
        }
        return value.trim();
    }

    private static String normalizeEmail(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeName(String value) {
        var normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > 180) {
            throw error(HttpStatus.BAD_REQUEST, "fullName is required and must not exceed 180 characters");
        }
        return normalized;
    }

    private static String normalizeReason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) {
            throw error(HttpStatus.BAD_REQUEST, "reason must contain between 8 and 500 characters");
        }
        return normalized;
    }

    private static UUID normalizeCorrelationId(String value) {
        if (value == null || value.isBlank()) return UUID.randomUUID();
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException invalid) {
            throw error(HttpStatus.BAD_REQUEST, "X-Correlation-Id must be a UUID");
        }
    }

    private static UUID keycloakSubject(String subject) {
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("Keycloak user subject must be a UUID", invalid);
        }
    }

    private static void verifyRequestHash(String stored, String candidate) {
        if (!MessageDigest.isEqual(stored.getBytes(StandardCharsets.US_ASCII),
            candidate.getBytes(StandardCharsets.US_ASCII))) {
            throw error(HttpStatus.CONFLICT,
                "Idempotency-Key was already used with different invitation data");
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static ResponseStatusException error(HttpStatus status, String code) {
        return new ResponseStatusException(status, code);
    }

    private record AccountProvisionedData(
        UUID accountId,
        String realm,
        String email,
        String displayName,
        String provisioningMode,
        OffsetDateTime provisionedAt
    ) {}

    private record InvitationRow(
        UUID invitationId,
        UUID accountId,
        String keycloakSubject,
        String email,
        String displayName,
        String requestHash,
        String actionDispatchStatus,
        OffsetDateTime expiresAt,
        OffsetDateTime createdAt
    ) {}

    private record DispatchOutcome(
        InvitedAccount account,
        RestClientException failure
    ) {
        private static DispatchOutcome sent(InvitedAccount account) {
            return new DispatchOutcome(account, null);
        }

        private static DispatchOutcome failed(RestClientException failure) {
            return new DispatchOutcome(null, failure);
        }
    }

    public record InvitedAccount(
        UUID invitationId,
        UUID accountId,
        String email,
        String displayName,
        String deliveryStatus,
        OffsetDateTime expiresAt,
        OffsetDateTime createdAt,
        boolean replayed
    ) {}
}
