package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;
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
public class AuthService {
    public static final String BACKOFFICE_ACCOUNT_PROVISIONED = "vistay.auth.account-provisioned";

    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final ObjectMapper json;
    private final TransactionTemplate transactions;

    public AuthService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        TransactionTemplate transactions
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.json = json;
        this.transactions = transactions;
    }

    public ProvisionedAccount bootstrapBackoffice(
        String idempotencyKey,
        String email,
        String fullName,
        String temporaryPassword,
        String reason,
        String correlationId
    ) {
        var normalizedKey = requireIdempotencyKey(idempotencyKey);
        var previous = findByIdempotencyKey(normalizedKey);
        if (previous != null) {
            return validatePrevious(previous, normalizedEmail(email), fullName.trim(),
                normalizeReason(reason));
        }
        reserveBootstrap(normalizedKey);
        return provisionBackoffice(normalizedKey, null, email, fullName, temporaryPassword,
            reason, correlationId, "BOOTSTRAP");
    }

    public ProvisionedAccount provisionBackoffice(
        String idempotencyKey,
        UUID actorAccountId,
        String email,
        String fullName,
        String temporaryPassword,
        String reason,
        String correlationId
    ) {
        if (actorAccountId == null) {
            throw new IllegalArgumentException("actorAccountId is required for standard provisioning");
        }
        return provisionBackoffice(idempotencyKey, actorAccountId, email, fullName,
            temporaryPassword, reason, correlationId, "STANDARD");
    }

    private ProvisionedAccount provisionBackoffice(
        String idempotencyKey,
        UUID actorAccountId,
        String email,
        String fullName,
        String temporaryPassword,
        String reason,
        String correlationId,
        String provisioningMode
    ) {
        var normalizedKey = requireIdempotencyKey(idempotencyKey);
        var normalizedEmail = normalizedEmail(email);
        var normalizedName = fullName.trim();
        var normalizedReason = normalizeReason(reason);
        var normalizedCorrelationId = normalizeCorrelationId(correlationId);
        var requestHash = requestHashV2(
            normalizedEmail, normalizedName, normalizedReason
        );

        var previous = findByIdempotencyKey(normalizedKey);
        if (previous != null) {
            return validatePrevious(previous, normalizedEmail, normalizedName,
                normalizedReason);
        }
        if (findByEmail(normalizedEmail) != null) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "BACKOFFICE_ACCOUNT_ALREADY_EXISTS"
            );
        }

        var provisioningReference = deterministicAccountId(normalizedKey);
        String subject;
        try {
            subject = keycloak.ensureBackofficeUser(
                normalizedEmail,
                normalizedName,
                temporaryPassword,
                provisioningReference
            );
        } catch (RestClientException identityProviderFailure) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "IDENTITY_PROVIDER_UNAVAILABLE",
                identityProviderFailure
            );
        }
        var identityAccountId = keycloakSubject(subject);

        try {
            return transactions.execute(status -> persistProvisioning(
                normalizedKey,
                requestHash,
                actorAccountId,
                identityAccountId,
                subject,
                normalizedEmail,
                normalizedName,
                normalizedReason,
                normalizedCorrelationId,
                provisioningMode
            ));
        } catch (DataIntegrityViolationException concurrentRequest) {
            var winner = findByIdempotencyKey(normalizedKey);
            if (winner != null && MessageDigest.isEqual(
                winner.requestHash().getBytes(StandardCharsets.US_ASCII),
                requestHash.getBytes(StandardCharsets.US_ASCII)
            )) {
                return validatePrevious(winner, normalizedEmail, normalizedName,
                    normalizedReason);
            }
            throw concurrentRequest;
        }
    }

    private ProvisionedAccount persistProvisioning(
        String idempotencyKey,
        String requestHash,
        UUID actorAccountId,
        UUID identityAccountId,
        String subject,
        String email,
        String fullName,
        String reason,
        String correlationId,
        String provisioningMode
    ) {
        var inserted = jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, 'vistay-backoffice', :subject, 'ADMIN', :email, 'ACTIVE')
            ON CONFLICT DO NOTHING
            RETURNING id, subject, email, account_type, status, version, created_at
            """)
            .param("id", identityAccountId)
            .param("subject", subject)
            .param("email", email)
            .query(ProvisionedAccount.class)
            .optional()
            .orElse(null);

        if (inserted == null) {
            var concurrentRetry = findByIdempotencyKey(idempotencyKey);
            if (concurrentRetry != null && MessageDigest.isEqual(
                concurrentRetry.requestHash().getBytes(StandardCharsets.US_ASCII),
                requestHash.getBytes(StandardCharsets.US_ASCII)
            )) {
                return concurrentRetry.account();
            }
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "BACKOFFICE_ACCOUNT_ALREADY_EXISTS"
            );
        }

        var persisted = jdbc.sql("""
            SELECT id, subject, email, account_type, status, version, created_at
            FROM identity_accounts WHERE id = :id
            """)
            .param("id", inserted.id())
            .query(ProvisionedAccount.class)
            .single();

        jdbc.sql("""
            INSERT INTO provisioning_requests(
                idempotency_key, request_hash, request_hash_version, identity_account_id,
                actor_account_id, reason, correlation_id, provisioning_mode, completed_at
            ) VALUES (
                :key, :requestHash, 2, :accountId,
                :actorAccountId, :reason, :correlationId, :provisioningMode, now()
            )
            """)
            .param("key", idempotencyKey)
            .param("requestHash", requestHash)
            .param("accountId", persisted.id())
            .param("actorAccountId", actorAccountId)
            .param("reason", reason)
            .param("correlationId", UUID.fromString(correlationId))
            .param("provisioningMode", provisioningMode)
            .update();

        var data = writeJson(new AccountProvisionedData(
            persisted.id(), "BACKOFFICE", persisted.email(), fullName, provisioningMode,
            OffsetDateTime.now(ZoneOffset.UTC)
        ));
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                'IdentityAccount', :aggregateId, :aggregateVersion, :eventType,
                1, CAST(:payload AS jsonb), :correlationId
            )
            """)
            .param("aggregateId", persisted.id())
            .param("aggregateVersion", persisted.version() + 1)
            .param("eventType", BACKOFFICE_ACCOUNT_PROVISIONED)
            .param("payload", data)
            .param("correlationId", correlationId)
            .update();
        if ("BOOTSTRAP".equals(provisioningMode)) {
            jdbc.sql("""
                UPDATE authentication_bootstrap_state
                SET identity_account_id = :accountId, completed_at = now()
                WHERE singleton AND reservation_key = :key AND completed_at IS NULL
                """)
                .param("accountId", persisted.id())
                .param("key", idempotencyKey)
                .update();
        }
        return persisted;
    }

    private void reserveBootstrap(String idempotencyKey) {
        transactions.executeWithoutResult(status -> {
            var state = jdbc.sql("""
                SELECT reservation_key, completed_at FROM authentication_bootstrap_state
                WHERE singleton FOR UPDATE
                """).query(BootstrapState.class).single();
            if (state.completedAt() != null) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "BOOTSTRAP_ALREADY_COMPLETED");
            }
            if (state.reservationKey() != null && !state.reservationKey().equals(idempotencyKey)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "BOOTSTRAP_ALREADY_RESERVED");
            }
            jdbc.sql("""
                UPDATE authentication_bootstrap_state SET reservation_key = :key WHERE singleton
                """).param("key", idempotencyKey).update();
        });
    }

    private static ProvisionedAccount validatePrevious(
        PreviousProvisioning previous,
        String normalizedEmail,
        String normalizedName,
        String normalizedReason
    ) {
        var requestHash = previous.requestHashVersion() == 1
            ? sha256(normalizedEmail + "\n" + normalizedName)
            : requestHashV2(normalizedEmail, normalizedName, normalizedReason);
        if (!MessageDigest.isEqual(
            previous.requestHash().getBytes(StandardCharsets.US_ASCII),
            requestHash.getBytes(StandardCharsets.US_ASCII)
        )) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "Idempotency-Key was already used with different account data"
            );
        }
        return previous.account();
    }

    private ProvisionedAccount findByEmail(String email) {
        return jdbc.sql("""
            SELECT id, subject, email, account_type, status, version, created_at
            FROM identity_accounts
            WHERE realm = 'vistay-backoffice' AND email = :email
            """)
            .param("email", email)
            .query(ProvisionedAccount.class)
            .optional()
            .orElse(null);
    }

    private PreviousProvisioning findByIdempotencyKey(String key) {
        return jdbc.sql("""
            SELECT pr.request_hash, pr.request_hash_version, ia.id, ia.subject, ia.email, ia.account_type,
                   ia.status, ia.version, ia.created_at
            FROM provisioning_requests pr
            JOIN identity_accounts ia ON ia.id = pr.identity_account_id
            WHERE pr.idempotency_key = :key AND pr.completed_at IS NOT NULL
            """)
            .param("key", key)
            .query((rs, rowNum) -> new PreviousProvisioning(
                rs.getString("request_hash"),
                rs.getInt("request_hash_version"),
                new ProvisionedAccount(
                    rs.getObject("id", UUID.class),
                    rs.getString("subject"),
                    rs.getString("email"),
                    rs.getString("account_type"),
                    rs.getString("status"),
                    rs.getLong("version"),
                    rs.getObject("created_at", OffsetDateTime.class)
                )
            ))
            .optional()
            .orElse(null);
    }

    private String writeJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize account provisioning event", failure);
        }
    }

    private static String requireIdempotencyKey(String value) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Idempotency-Key is required and must not exceed 160 characters"
            );
        }
        return value.trim();
    }

    private static String normalizedEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeReason(String reason) {
        var normalized = reason == null ? "" : reason.trim();
        if (normalized.length() < 8 || normalized.length() > 500) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "reason must contain between 8 and 500 characters"
            );
        }
        return normalized;
    }

    private static UUID deterministicAccountId(String idempotencyKey) {
        return UUID.nameUUIDFromBytes(("vistay:backoffice:" + idempotencyKey)
            .getBytes(StandardCharsets.UTF_8));
    }

    private static UUID keycloakSubject(String subject) {
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("Keycloak user subject must be a UUID", invalid);
        }
    }

    private static String normalizeCorrelationId(String value) {
        if (value == null || value.isBlank()) {
            return UUID.randomUUID().toString();
        }
        try {
            return UUID.fromString(value.trim()).toString();
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "X-Correlation-Id must be a UUID"
            );
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String requestHashV2(
        String email,
        String fullName,
        String reason
    ) {
        return sha256(String.join("\n", "v2", email, fullName, reason));
    }

    private record PreviousProvisioning(
        String requestHash,
        int requestHashVersion,
        ProvisionedAccount account
    ) {}
    private record BootstrapState(String reservationKey, OffsetDateTime completedAt) {}

    private record AccountProvisionedData(
        UUID accountId,
        String realm,
        String email,
        String displayName,
        String provisioningMode,
        OffsetDateTime provisionedAt
    ) {}

    public record ProvisionedAccount(
        UUID id,
        String subject,
        String email,
        String accountType,
        String status,
        long version,
        OffsetDateTime createdAt
    ) {}
}
