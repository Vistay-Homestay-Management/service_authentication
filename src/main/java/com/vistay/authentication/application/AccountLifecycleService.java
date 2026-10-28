package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.BruteForceStatus;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AccountLifecycleService {
    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final TransactionTemplate transactions;

    public AccountLifecycleService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        TransactionTemplate transactions
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.transactions = transactions;
    }

    public AccountSecurityView get(UUID accountId) {
        var account = account(accountId, false);
        try {
            return new AccountSecurityView(account, keycloak.bruteForceStatus(accountId));
        } catch (RestClientException failure) {
            throw identityProviderUnavailable(failure);
        }
    }

    public List<LifecycleEvent> events(UUID accountId) {
        requireAccount(accountId);
        return jdbc.sql("""
            SELECT idempotency_key, actor_account_id, target_account_id, action,
                   previous_status, resulting_status, resulting_version,
                   reason, correlation_id, created_at, completed_at
            FROM account_lifecycle_requests
            WHERE target_account_id = :accountId AND completed_at IS NOT NULL
            ORDER BY created_at DESC LIMIT 200
            """)
            .param("accountId", accountId)
            .query(LifecycleEvent.class)
            .list();
    }

    public LifecycleResult change(
        String idempotencyKey,
        UUID actorAccountId,
        UUID targetAccountId,
        LifecycleAction action,
        long expectedVersion,
        String reason,
        String correlationId
    ) {
        if (actorAccountId.equals(targetAccountId)) {
            throw error(HttpStatus.BAD_REQUEST, "CANNOT_CHANGE_OWN_ACCOUNT_STATUS");
        }
        var key = requireKey(idempotencyKey);
        var normalizedReason = requireReason(reason);
        var correlation = correlationId(correlationId);
        var hash = sha256(String.join("\n", actorAccountId.toString(), targetAccountId.toString(),
            action.name(), Long.toString(expectedVersion), normalizedReason));

        try {
            return transactions.execute(status -> {
                var previous = reservation(key);
                if (previous != null) {
                    if (!MessageDigest.isEqual(previous.requestHash().getBytes(StandardCharsets.US_ASCII),
                        hash.getBytes(StandardCharsets.US_ASCII))) {
                        throw error(HttpStatus.CONFLICT, "IDEMPOTENCY_KEY_REUSED");
                    }
                    if (previous.completedAt() != null) return result(previous, true);
                    throw error(HttpStatus.CONFLICT, "ACCOUNT_CHANGE_IN_PROGRESS");
                }

                var current = account(targetAccountId, true);
                if (current.version() != expectedVersion) {
                    throw error(HttpStatus.CONFLICT, "VERSION_CONFLICT");
                }
                var desired = resultingStatus(current.status(), action);
                jdbc.sql("""
                    INSERT INTO account_lifecycle_requests(
                        idempotency_key, request_hash, actor_account_id, target_account_id,
                        action, previous_status, resulting_status, expected_version,
                        reason, correlation_id
                    ) VALUES (
                        :key, :hash, :actor, :target, :action, :previous, :resulting,
                        :expectedVersion, :reason, :correlation
                    )
                    """)
                    .param("key", key).param("hash", hash).param("actor", actorAccountId)
                    .param("target", targetAccountId).param("action", action.name())
                    .param("previous", current.status()).param("resulting", desired)
                    .param("expectedVersion", expectedVersion).param("reason", normalizedReason)
                    .param("correlation", correlation).update();

                applyKeycloak(targetAccountId, action);
                var updated = jdbc.sql("""
                    UPDATE identity_accounts
                    SET status = :status, version = version + 1, updated_at = now()
                    WHERE id = :id AND version = :expectedVersion
                    RETURNING id, email::text AS email, status, version, updated_at
                    """)
                    .param("status", desired).param("id", targetAccountId)
                    .param("expectedVersion", expectedVersion)
                    .query(AccountView.class).optional()
                    .orElseThrow(() -> error(HttpStatus.CONFLICT, "VERSION_CONFLICT"));
                jdbc.sql("""
                    UPDATE account_lifecycle_requests
                    SET resulting_version = :version, completed_at = now()
                    WHERE idempotency_key = :key
                    """)
                    .param("version", updated.version()).param("key", key).update();
                return result(reservation(key), false);
            });
        } catch (RestClientException failure) {
            throw identityProviderUnavailable(failure);
        }
    }

    private void applyKeycloak(UUID accountId, LifecycleAction action) {
        if (action == LifecycleAction.RECOVER) {
            keycloak.clearUserLoginFailures(accountId);
            keycloak.setUserEnabled(accountId, true);
        } else {
            keycloak.setUserEnabled(accountId, false);
            keycloak.logoutUser(accountId);
        }
    }

    private AccountView account(UUID accountId, boolean lock) {
        var suffix = lock ? " FOR UPDATE" : "";
        return jdbc.sql("""
            SELECT id, email::text AS email, status, version, updated_at
            FROM identity_accounts WHERE id = :id
            """ + suffix)
            .param("id", accountId).query(AccountView.class).optional()
            .orElseThrow(() -> error(HttpStatus.NOT_FOUND, "BACKOFFICE_ACCOUNT_NOT_FOUND"));
    }

    private void requireAccount(UUID accountId) { account(accountId, false); }

    private Reservation reservation(String key) {
        return jdbc.sql("""
            SELECT idempotency_key, request_hash, actor_account_id, target_account_id,
                   action, previous_status, resulting_status, resulting_version,
                   reason, correlation_id, created_at, completed_at
            FROM account_lifecycle_requests WHERE idempotency_key = :key
            """)
            .param("key", key).query(Reservation.class).optional().orElse(null);
    }

    private static LifecycleResult result(Reservation row, boolean replayed) {
        return new LifecycleResult(row.targetAccountId(), row.action(), row.previousStatus(),
            row.resultingStatus(), row.resultingVersion(), row.completedAt(), replayed);
    }

    private static String resultingStatus(String status, LifecycleAction action) {
        return switch (action) {
            case LOCK -> {
                if (!"ACTIVE".equals(status)) throw error(HttpStatus.CONFLICT, "ACCOUNT_NOT_ACTIVE");
                yield "LOCKED";
            }
            case DISABLE -> {
                if ("DISABLED".equals(status) || "CLOSED".equals(status))
                    throw error(HttpStatus.CONFLICT, "ACCOUNT_CANNOT_BE_DISABLED");
                yield "DISABLED";
            }
            case RECOVER -> {
                if (!"LOCKED".equals(status) && !"DISABLED".equals(status))
                    throw error(HttpStatus.CONFLICT, "ACCOUNT_NOT_RECOVERABLE");
                yield "ACTIVE";
            }
        };
    }

    private static String requireKey(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160)
            throw error(HttpStatus.BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY");
        return normalized;
    }

    private static String requireReason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500)
            throw error(HttpStatus.BAD_REQUEST, "INVALID_LIFECYCLE_REASON");
        return normalized;
    }

    private static UUID correlationId(String value) {
        try { return value == null || value.isBlank() ? UUID.randomUUID() : UUID.fromString(value.trim()); }
        catch (IllegalArgumentException invalid) { throw error(HttpStatus.BAD_REQUEST, "INVALID_CORRELATION_ID"); }
    }

    private static String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static ResponseStatusException error(HttpStatus status, String code) {
        return new ResponseStatusException(status, code);
    }

    private static ResponseStatusException identityProviderUnavailable(RestClientException failure) {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "IDENTITY_PROVIDER_UNAVAILABLE", failure);
    }

    public enum LifecycleAction { LOCK, DISABLE, RECOVER }
    public record AccountView(UUID id, String email, String status, long version, OffsetDateTime updatedAt) {}
    public record AccountSecurityView(AccountView account, BruteForceStatus bruteForce) {}
    public record LifecycleResult(UUID targetAccountId, String action, String previousStatus,
        String status, Long version, OffsetDateTime completedAt, boolean replayed) {}
    public record LifecycleEvent(String idempotencyKey, UUID actorAccountId, UUID targetAccountId,
        String action, String previousStatus, String resultingStatus, Long resultingVersion,
        String reason, UUID correlationId, OffsetDateTime createdAt, OffsetDateTime completedAt) {}
    private record Reservation(String idempotencyKey, String requestHash, UUID actorAccountId,
        UUID targetAccountId, String action, String previousStatus, String resultingStatus,
        Long resultingVersion, String reason, UUID correlationId,
        OffsetDateTime createdAt, OffsetDateTime completedAt) {}
}
