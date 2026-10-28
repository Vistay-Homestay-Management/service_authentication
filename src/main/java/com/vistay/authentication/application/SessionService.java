package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.ActiveSession;
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
public class SessionService {
    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final TransactionTemplate transactions;

    public SessionService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        TransactionTemplate transactions
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.transactions = transactions;
    }

    public List<ActiveSession> list(UUID targetAccountId) {
        ensureProjectedAccount(targetAccountId);
        try {
            return keycloak.listUserSessions(targetAccountId);
        } catch (RestClientException failure) {
            throw identityProviderUnavailable(failure);
        }
    }

    public RevocationResult revoke(
        String idempotencyKey,
        UUID actorAccountId,
        UUID targetAccountId,
        String sessionId,
        String reason,
        String correlationId
    ) {
        var key = requireIdempotencyKey(idempotencyKey);
        var normalizedSessionId = requireSessionId(sessionId);
        var normalizedReason = requireReason(reason);
        var normalizedCorrelationId = correlationId(correlationId);
        ensureProjectedAccount(targetAccountId);
        var requestHash = sha256(String.join("\n",
            actorAccountId.toString(), targetAccountId.toString(), normalizedSessionId, normalizedReason));

        var inserted = jdbc.sql("""
            INSERT INTO session_revocation_requests(
                idempotency_key, request_hash, actor_account_id, target_account_id,
                keycloak_session_id, reason, correlation_id
            ) VALUES (:key, :hash, :actor, :target, :session, :reason, :correlation)
            ON CONFLICT DO NOTHING
            """)
            .param("key", key)
            .param("hash", requestHash)
            .param("actor", actorAccountId)
            .param("target", targetAccountId)
            .param("session", normalizedSessionId)
            .param("reason", normalizedReason)
            .param("correlation", normalizedCorrelationId)
            .update() == 1;

        var reservation = reservation(key);
        if (!MessageDigest.isEqual(
            reservation.requestHash().getBytes(StandardCharsets.US_ASCII),
            requestHash.getBytes(StandardCharsets.US_ASCII)
        )) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "IDEMPOTENCY_KEY_REUSED");
        }
        if (!inserted) {
            if (reservation.completedAt() != null) {
                return result(reservation, true);
            }
            var sessions = list(targetAccountId);
            if (sessions.stream().noneMatch(session -> session.id().equals(normalizedSessionId))) {
                return complete(reservation, true);
            }
            throw new ResponseStatusException(HttpStatus.CONFLICT, "SESSION_REVOCATION_IN_PROGRESS");
        }

        try {
            var sessions = keycloak.listUserSessions(targetAccountId);
            if (sessions.stream().noneMatch(session -> session.id().equals(normalizedSessionId))) {
                removeIncomplete(key);
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "ACTIVE_SESSION_NOT_FOUND");
            }
            keycloak.revokeSession(normalizedSessionId);
            return complete(reservation, false);
        } catch (ResponseStatusException expected) {
            throw expected;
        } catch (RestClientException failure) {
            removeIncomplete(key);
            throw identityProviderUnavailable(failure);
        }
    }

    private RevocationResult complete(Reservation reservation, boolean replayed) {
        return transactions.execute(status -> {
            jdbc.sql("""
                UPDATE session_revocation_requests
                SET completed_at = now()
                WHERE idempotency_key = :key AND completed_at IS NULL
                """)
                .param("key", reservation.idempotencyKey())
                .update();
            var completed = reservation(reservation.idempotencyKey());
            return result(completed, replayed);
        });
    }

    private Reservation reservation(String key) {
        return jdbc.sql("""
            SELECT idempotency_key, request_hash, actor_account_id, target_account_id,
                   keycloak_session_id AS session_id, reason, correlation_id, completed_at
            FROM session_revocation_requests
            WHERE idempotency_key = :key
            """)
            .param("key", key)
            .query(Reservation.class)
            .optional()
            .orElseThrow(() -> new IllegalStateException("Session revocation reservation was not persisted"));
    }

    private void ensureProjectedAccount(UUID accountId) {
        var exists = jdbc.sql("SELECT count(*) FROM identity_accounts WHERE id = :id")
            .param("id", accountId)
            .query(Long.class)
            .single();
        if (exists == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "BACKOFFICE_ACCOUNT_NOT_FOUND");
        }
    }

    private void removeIncomplete(String key) {
        jdbc.sql("DELETE FROM session_revocation_requests WHERE idempotency_key = :key AND completed_at IS NULL")
            .param("key", key)
            .update();
    }

    private static RevocationResult result(Reservation reservation, boolean replayed) {
        return new RevocationResult(
            reservation.targetAccountId(), reservation.sessionId(), reservation.completedAt(), replayed
        );
    }

    private static ResponseStatusException identityProviderUnavailable(RestClientException failure) {
        return new ResponseStatusException(
            HttpStatus.SERVICE_UNAVAILABLE, "IDENTITY_PROVIDER_UNAVAILABLE", failure
        );
    }

    private static String requireIdempotencyKey(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY");
        }
        return normalized;
    }

    private static String requireSessionId(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 128) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_SESSION_ID");
        }
        return normalized;
    }

    private static String requireReason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_REVOCATION_REASON");
        }
        return normalized;
    }

    private static UUID correlationId(String value) {
        if (value == null || value.isBlank()) {
            return UUID.randomUUID();
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_CORRELATION_ID");
        }
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

    private record Reservation(
        String idempotencyKey,
        String requestHash,
        UUID actorAccountId,
        UUID targetAccountId,
        String sessionId,
        String reason,
        UUID correlationId,
        OffsetDateTime completedAt
    ) {}

    public record RevocationResult(
        UUID targetAccountId,
        String sessionId,
        OffsetDateTime revokedAt,
        boolean replayed
    ) {}
}
