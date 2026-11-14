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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ProfileAccountAdministrationService {
    private final JdbcClient jdbc;
    private final KeycloakAdminClient keycloak;
    private final TransactionTemplate transactions;
    private final Duration invitationTtl;
    private final Duration hostLinkDeadline;
    private final Duration adminLinkDeadline;

    public ProfileAccountAdministrationService(
        JdbcClient jdbc,
        KeycloakAdminClient keycloak,
        TransactionTemplate transactions,
        @Value("${vistay.profile-account.invitation-ttl:PT24H}") Duration invitationTtl,
        @Value("${vistay.profile-link.host-deadline:PT168H}") Duration hostLinkDeadline,
        @Value("${vistay.profile-link.admin-deadline:PT72H}") Duration adminLinkDeadline
    ) {
        this.jdbc = jdbc;
        this.keycloak = keycloak;
        this.transactions = transactions;
        this.invitationTtl = invitationTtl;
        this.hostLinkDeadline = hostLinkDeadline;
        this.adminLinkDeadline = adminLinkDeadline;
    }

    public ProfileAccountResult execute(UUID actorAccountId, String idempotencyKey, Command command) {
        var key = key(idempotencyKey);
        var type = accountType(command.accountType());
        var mode = mode(command.mode());
        var email = email(command.email());
        var name = name(command.displayName());
        var reason = reason(command.reason());
        var password = password(mode, command.temporaryPassword());
        if (actorAccountId == null || command.profileId() == null) {
            throw error(HttpStatus.BAD_REQUEST, "INVALID_PROFILE_ACCOUNT_REQUEST");
        }
        var fingerprint = sha256(String.join("\n", "profile-account-admin-v1", type,
            command.profileId().toString(), mode, email, name, reason,
            password == null ? "" : sha256(password)));
        var existing = findByKey(key);
        if (existing != null) return replayOrDispatch(existing, fingerprint, true);

        var requestId = UUID.nameUUIDFromBytes(("vistay:profile-account:" + key)
            .getBytes(StandardCharsets.UTF_8));
        String subject;
        try {
            subject = keycloak.ensureProfileAccount(
                type, email, name, password, requestId, command.profileId());
        } catch (KeycloakAdminClient.ProfileAccountCollisionException collision) {
            throw error(HttpStatus.CONFLICT, "PROFILE_ACCOUNT_ALREADY_EXISTS");
        } catch (RestClientException unavailable) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "IDENTITY_PROVIDER_UNAVAILABLE", unavailable);
        }
        var accountId = subjectId(subject);
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        var expiresAt = "INVITATION".equals(mode) ? now.plus(invitationTtl) : null;
        var linkDeadline = switch (type) {
            case "HOST" -> now.plus(hostLinkDeadline);
            case "ADMIN" -> now.plus(adminLinkDeadline);
            case "CUSTOMER" -> null;
            default -> throw new IllegalStateException("Unsupported account type");
        };

        try {
            transactions.executeWithoutResult(status -> {
                jdbc.sql("""
                    INSERT INTO identity_accounts(
                        id, realm, subject, account_type, email, status, profile_link_deadline
                    ) VALUES (
                        :id, :realm, :subject, :accountType, :email, 'PENDING_PROFILE', :linkDeadline
                    )
                    """).param("id", accountId).param("realm", realm(type)).param("subject", subject)
                    .param("accountType", type).param("email", email)
                    .param("linkDeadline", linkDeadline, java.sql.Types.TIMESTAMP_WITH_TIMEZONE).update();
                jdbc.sql("""
                    INSERT INTO profile_account_administration(
                        request_id, target_profile_id, account_type, account_id,
                        email, display_name, mode, delivery_status, idempotency_key,
                        request_hash, actor_account_id, reason, expires_at
                    ) VALUES (
                        :requestId, :profileId, :accountType, :accountId,
                        :email, :displayName, :mode, :deliveryStatus, :key,
                        :requestHash, :actor, :reason, :expiresAt
                    )
                    """).param("requestId", requestId).param("profileId", command.profileId())
                    .param("accountType", type).param("accountId", accountId).param("email", email)
                    .param("displayName", name).param("mode", mode)
                    .param("deliveryStatus", "INVITATION".equals(mode) ? "PENDING" : "NOT_REQUIRED")
                    .param("key", key).param("requestHash", fingerprint).param("actor", actorAccountId)
                    .param("reason", reason).param("expiresAt", expiresAt, java.sql.Types.TIMESTAMP_WITH_TIMEZONE)
                    .update();
            });
        } catch (DataIntegrityViolationException conflict) {
            var winner = findByKey(key);
            if (winner != null) return replayOrDispatch(winner, fingerprint, true);
            throw error(HttpStatus.CONFLICT, "PROFILE_ACCOUNT_ALREADY_EXISTS");
        }
        return replayOrDispatch(requireByKey(key), fingerprint, false);
    }

    private ProfileAccountResult replayOrDispatch(RequestRow row, String fingerprint, boolean replayed) {
        verifyFingerprint(row.requestHash(), fingerprint);
        if (!"INVITATION".equals(row.mode()) || "SENT".equals(row.deliveryStatus())) {
            return view(row, replayed);
        }
        if (row.expiresAt() == null || !OffsetDateTime.now(ZoneOffset.UTC).isBefore(row.expiresAt())) {
            throw error(HttpStatus.CONFLICT, "PROFILE_ACCOUNT_INVITATION_EXPIRED");
        }
        try {
            keycloak.sendProfileAccountActivationEmail(row.accountType(), row.accountId().toString());
            jdbc.sql("""
                UPDATE profile_account_administration
                SET delivery_status = 'SENT', updated_at = now()
                WHERE request_id = :id AND delivery_status <> 'SENT'
                """).param("id", row.requestId()).update();
            return view(requireByKey(row.idempotencyKey()), replayed);
        } catch (RestClientException unavailable) {
            jdbc.sql("""
                UPDATE profile_account_administration
                SET delivery_status = 'RETRY_REQUIRED', updated_at = now()
                WHERE request_id = :id AND delivery_status <> 'SENT'
                """).param("id", row.requestId()).update();
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "PROFILE_ACCOUNT_INVITATION_DISPATCH_UNAVAILABLE", unavailable);
        }
    }

    private RequestRow findByKey(String key) {
        return jdbc.sql("""
            SELECT request_id, target_profile_id, account_type, account_id,
                   email::text AS email, display_name, mode, delivery_status,
                   idempotency_key, request_hash, expires_at, created_at
            FROM profile_account_administration WHERE idempotency_key = :key
            """).param("key", key).query(RequestRow.class).optional().orElse(null);
    }

    private RequestRow requireByKey(String key) {
        var row = findByKey(key);
        if (row == null) throw new IllegalStateException("Profile account request was not persisted");
        return row;
    }

    private static ProfileAccountResult view(RequestRow row, boolean replayed) {
        return new ProfileAccountResult(row.requestId(), row.targetProfileId(), row.accountType(),
            row.accountId(), row.email(), row.displayName(), row.mode(), row.deliveryStatus(),
            row.expiresAt(), row.createdAt(), replayed);
    }

    public static String permission(String accountType) {
        return switch (accountType(accountType)) {
            case "CUSTOMER" -> "customer-account:provision";
            case "HOST" -> "host-account:provision";
            case "ADMIN" -> "admin-account:provision";
            default -> throw new IllegalStateException("Unsupported account type");
        };
    }

    private static String accountType(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("CUSTOMER|ADMIN|HOST")) throw error(HttpStatus.BAD_REQUEST, "INVALID_ACCOUNT_TYPE");
        return normalized;
    }

    private static String mode(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("DIRECT|INVITATION")) throw error(HttpStatus.BAD_REQUEST, "INVALID_ACCOUNT_MODE");
        return normalized;
    }

    private static String email(String value) {
        var normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") || normalized.length() > 320) throw error(HttpStatus.BAD_REQUEST, "INVALID_ACCOUNT_EMAIL");
        return normalized;
    }

    private static String name(String value) {
        var normalized = value == null ? "" : value.trim().replaceAll("\\s+", " ");
        if (normalized.isEmpty() || normalized.length() > 180) throw error(HttpStatus.BAD_REQUEST, "INVALID_DISPLAY_NAME");
        return normalized;
    }

    private static String reason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) throw error(HttpStatus.BAD_REQUEST, "INVALID_REASON");
        return normalized;
    }

    private static String password(String mode, String value) {
        if ("INVITATION".equals(mode)) return null;
        if (value == null || value.length() < 12 || value.length() > 128) throw error(HttpStatus.BAD_REQUEST, "INVALID_TEMPORARY_PASSWORD");
        return value;
    }

    private static String key(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) throw error(HttpStatus.BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY");
        return normalized;
    }

    private static UUID subjectId(String value) {
        try { return UUID.fromString(value); }
        catch (IllegalArgumentException invalid) { throw new IllegalStateException("Keycloak subject must be a UUID", invalid); }
    }

    private static String realm(String accountType) {
        return switch (accountType) {
            case "CUSTOMER" -> "vistay-customer";
            case "HOST" -> "vistay-host";
            case "ADMIN" -> "vistay-backoffice";
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
    }

    private static void verifyFingerprint(String persisted, String candidate) {
        if (!MessageDigest.isEqual(persisted.getBytes(StandardCharsets.US_ASCII),
            candidate.getBytes(StandardCharsets.US_ASCII))) {
            throw error(HttpStatus.CONFLICT, "IDEMPOTENCY_CONFLICT");
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static ResponseStatusException error(HttpStatus status, String code) {
        return new ResponseStatusException(status, code);
    }

    public record Command(UUID profileId, String accountType, String email, String displayName,
                          String mode, String temporaryPassword, String reason) {}
    public record ProfileAccountResult(UUID requestId, UUID profileId, String accountType,
                                       UUID accountId, String email, String displayName,
                                       String mode, String deliveryStatus, OffsetDateTime expiresAt,
                                       OffsetDateTime createdAt, boolean replayed) {}
    private record RequestRow(UUID requestId, UUID targetProfileId, String accountType,
                              UUID accountId, String email, String displayName, String mode,
                              String deliveryStatus, String idempotencyKey, String requestHash,
                              OffsetDateTime expiresAt, OffsetDateTime createdAt) {}
}
