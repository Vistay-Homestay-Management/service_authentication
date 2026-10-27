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
        String correlationId
    ) {
        var normalizedKey = requireIdempotencyKey(idempotencyKey);
        var previous = findByIdempotencyKey(normalizedKey);
        if (previous != null) {
            return validatePrevious(previous, normalizedEmail(email), fullName.trim());
        }
        reserveBootstrap(normalizedKey);
        return provisionBackoffice(normalizedKey, email, fullName, temporaryPassword, correlationId, "BOOTSTRAP");
    }

    public ProvisionedAccount provisionBackoffice(
        String idempotencyKey,
        String email,
        String fullName,
        String temporaryPassword,
        String correlationId
    ) {
        return provisionBackoffice(idempotencyKey, email, fullName, temporaryPassword, correlationId, "STANDARD");
    }

    private ProvisionedAccount provisionBackoffice(
        String idempotencyKey,
        String email,
        String fullName,
        String temporaryPassword,
        String correlationId,
        String provisioningMode
    ) {
        var normalizedKey = requireIdempotencyKey(idempotencyKey);
        var normalizedEmail = normalizedEmail(email);
        var normalizedName = fullName.trim();
        var requestHash = sha256(normalizedEmail + "\n" + normalizedName);

        var previous = findByIdempotencyKey(normalizedKey);
        if (previous != null) {
            return validatePrevious(previous, normalizedEmail, normalizedName);
        }

        var provisioningReference = deterministicAccountId(normalizedKey);
        var subject = keycloak.ensureBackofficeUser(
            normalizedEmail,
            normalizedName,
            temporaryPassword,
            provisioningReference
        );
        var identityAccountId = keycloakSubject(subject);

        try {
            return transactions.execute(status -> persistProvisioning(
                normalizedKey,
                requestHash,
                identityAccountId,
                subject,
                normalizedEmail,
                normalizedName,
                correlationId,
                provisioningMode
            ));
        } catch (DataIntegrityViolationException concurrentRequest) {
            var winner = findByIdempotencyKey(normalizedKey);
            if (winner != null && MessageDigest.isEqual(
                winner.requestHash().getBytes(StandardCharsets.US_ASCII),
                requestHash.getBytes(StandardCharsets.US_ASCII)
            )) {
                return winner.account();
            }
            throw concurrentRequest;
        }
    }

    private ProvisionedAccount persistProvisioning(
        String idempotencyKey,
        String requestHash,
        UUID identityAccountId,
        String subject,
        String email,
        String fullName,
        String correlationId,
        String provisioningMode
    ) {
        jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, 'vistay-backoffice', :subject, 'ADMIN', :email, 'ACTIVE')
            ON CONFLICT (realm, subject) DO UPDATE
            SET email = EXCLUDED.email, updated_at = now()
            """)
            .param("id", identityAccountId)
            .param("subject", subject)
            .param("email", email)
            .update();

        var persisted = jdbc.sql("""
            SELECT id, subject, email, account_type, status, version, created_at
            FROM identity_accounts
            WHERE realm = 'vistay-backoffice' AND subject = :subject
            """)
            .param("subject", subject)
            .query(ProvisionedAccount.class)
            .single();

        jdbc.sql("""
            INSERT INTO provisioning_requests(idempotency_key, request_hash, identity_account_id, completed_at)
            VALUES (:key, :requestHash, :accountId, now())
            """)
            .param("key", idempotencyKey)
            .param("requestHash", requestHash)
            .param("accountId", persisted.id())
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
            .param("correlationId", normalizeCorrelationId(correlationId))
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
        String normalizedName
    ) {
        var requestHash = sha256(normalizedEmail + "\n" + normalizedName);
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

    private PreviousProvisioning findByIdempotencyKey(String key) {
        return jdbc.sql("""
            SELECT pr.request_hash, ia.id, ia.subject, ia.email, ia.account_type,
                   ia.status, ia.version, ia.created_at
            FROM provisioning_requests pr
            JOIN identity_accounts ia ON ia.id = pr.identity_account_id
            WHERE pr.idempotency_key = :key AND pr.completed_at IS NOT NULL
            """)
            .param("key", key)
            .query((rs, rowNum) -> new PreviousProvisioning(
                rs.getString("request_hash"),
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

    private record PreviousProvisioning(String requestHash, ProvisionedAccount account) {}
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
