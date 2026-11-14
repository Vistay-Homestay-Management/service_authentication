package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class ProfileLinkAccountLifecycleService {
    public static final String LINK_REQUESTED = "vistay.user.profile-link-requested";
    public static final String PROFILE_LINKED = "vistay.user.profile-linked";
    private static final String CONSUMER_NAME = "authentication-profile-link-lifecycle-v1";
    private static final Logger log = LoggerFactory.getLogger(ProfileLinkAccountLifecycleService.class);

    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final KeycloakAdminClient keycloak;
    private final Duration hostDeadline;
    private final Duration adminDeadline;

    public ProfileLinkAccountLifecycleService(
        JdbcClient jdbc,
        ObjectMapper json,
        KeycloakAdminClient keycloak,
        @Value("${vistay.profile-link.host-deadline:PT168H}") Duration hostDeadline,
        @Value("${vistay.profile-link.admin-deadline:PT72H}") Duration adminDeadline
    ) {
        this.jdbc = jdbc;
        this.json = json;
        this.keycloak = keycloak;
        this.hostDeadline = hostDeadline;
        this.adminDeadline = adminDeadline;
    }

    @KafkaListener(
        topics = {
            "${vistay.topics.profile-link-requested:vistay.user.profile-link-requested.v1}",
            "${vistay.topics.profile-linked:vistay.user.profile-linked.v1}"
        },
        groupId = "${spring.application.name}-profile-link-lifecycle-v1"
    )
    @Transactional
    public void consume(String rawEnvelope) throws Exception {
        var envelope = json.readValue(rawEnvelope, EventEnvelope.class);
        if (envelope.version() != 1
            || (!LINK_REQUESTED.equals(envelope.type()) && !PROFILE_LINKED.equals(envelope.type()))) {
            throw new IllegalArgumentException("Unsupported profile link lifecycle event");
        }
        if (!markProcessed(envelope.eventId())) return;
        if (LINK_REQUESTED.equals(envelope.type())) onRequested(envelope.data());
        else onLinked(envelope.data());
    }

    private void onRequested(JsonNode data) {
        var accountId = UUID.fromString(requiredText(data, "accountId"));
        var accountType = accountType(requiredText(data, "accountType"));
        var email = requiredText(data, "email").trim().toLowerCase();
        var requestedAt = OffsetDateTime.parse(requiredText(data, "requestedAt"));
        var deadline = switch (accountType) {
            case "HOST" -> requestedAt.plus(hostDeadline);
            case "ADMIN" -> requestedAt.plus(adminDeadline);
            case "CUSTOMER" -> null;
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
        jdbc.sql("""
            INSERT INTO identity_accounts(
                id, realm, subject, account_type, email, status, profile_link_deadline
            ) VALUES (
                :id, :realm, :subject, :accountType, :email, 'PENDING_PROFILE', :deadline
            )
            ON CONFLICT (realm, subject) DO UPDATE
            SET email = EXCLUDED.email,
                updated_at = now()
            WHERE identity_accounts.status = 'PENDING_PROFILE'
            """)
            .param("id", accountId).param("realm", realm(accountType))
            .param("subject", accountId.toString()).param("accountType", accountType)
            .param("email", email)
            .param("deadline", deadline, java.sql.Types.TIMESTAMP_WITH_TIMEZONE)
            .update();

        jdbc.sql("""
            SELECT account_id, account_type, profile_id
            FROM pending_profile_link_completions
            WHERE account_id = :accountId
            """)
            .param("accountId", accountId)
            .query(PendingCompletion.class)
            .optional()
            .ifPresent(this::activatePendingCompletion);
    }

    private void onLinked(JsonNode data) {
        var accountId = UUID.fromString(requiredText(data, "accountId"));
        var profileId = UUID.fromString(requiredText(data, "profileId"));
        var accountType = accountType(requiredText(data, "profileType"));
        var updated = jdbc.sql("""
            UPDATE identity_accounts
            SET status = 'ACTIVE', profile_id = :profileId, linked_at = now(),
                profile_link_deadline = NULL, version = version + 1, updated_at = now()
            WHERE realm = :realm AND subject = :subject
            """)
            .param("profileId", profileId).param("realm", realm(accountType))
            .param("subject", accountId.toString()).update();
        if (updated == 0) {
            jdbc.sql("""
                INSERT INTO pending_profile_link_completions(account_id, account_type, profile_id)
                VALUES (:accountId, :accountType, :profileId)
                ON CONFLICT (account_id) DO UPDATE
                SET account_type = EXCLUDED.account_type,
                    profile_id = EXCLUDED.profile_id,
                    received_at = now()
                """)
                .param("accountId", accountId).param("accountType", accountType)
                .param("profileId", profileId).update();
            return;
        }
        keycloak.setProfileId(accountType, accountId, profileId.toString());
        keycloak.logoutUser(accountType, accountId);
    }

    private void activatePendingCompletion(PendingCompletion completion) {
        var updated = jdbc.sql("""
            UPDATE identity_accounts
            SET status = 'ACTIVE', profile_id = :profileId, linked_at = now(),
                profile_link_deadline = NULL, version = version + 1, updated_at = now()
            WHERE id = :accountId AND account_type = :accountType
            """)
            .param("profileId", completion.profileId())
            .param("accountId", completion.accountId())
            .param("accountType", completion.accountType())
            .update();
        if (updated != 1) throw new IllegalStateException("Pending identity account projection failed");
        keycloak.setProfileId(
            completion.accountType(), completion.accountId(), completion.profileId().toString());
        keycloak.logoutUser(completion.accountType(), completion.accountId());
        jdbc.sql("DELETE FROM pending_profile_link_completions WHERE account_id = :accountId")
            .param("accountId", completion.accountId()).update();
    }

    @Scheduled(fixedDelayString = "${vistay.profile-link.pending-reconcile-delay-ms:60000}")
    public void expirePendingPrivilegedAccounts() {
        var expired = jdbc.sql("""
            SELECT id, account_type
            FROM identity_accounts
            WHERE status = 'PENDING_PROFILE'
              AND account_type IN ('ADMIN', 'HOST')
              AND profile_link_deadline <= now()
            ORDER BY profile_link_deadline, id LIMIT 100
            """).query(ExpiredAccount.class).list();
        for (var account : expired) {
            try {
                keycloak.disableAndDeleteUser(account.accountType(), account.id());
                jdbc.sql("""
                    UPDATE identity_accounts
                    SET status = 'CLOSED', version = version + 1, updated_at = now()
                    WHERE id = :id AND status = 'PENDING_PROFILE'
                    """).param("id", account.id()).update();
                jdbc.sql("""
                    INSERT INTO security_audit_events(
                        account_type, account_id, event_type, success, details
                    ) VALUES (
                        :accountType, :accountId, 'PENDING_PROFILE_ACCOUNT_EXPIRED', true,
                        jsonb_build_object('expiredAt', :expiredAt)
                    )
                    """)
                    .param("accountType", account.accountType()).param("accountId", account.id())
                    .param("expiredAt", OffsetDateTime.now(ZoneOffset.UTC).toString()).update();
            } catch (RuntimeException failure) {
                log.warn("Pending profile account expiry failed accountType={} accountId={}",
                    account.accountType(), account.id(), failure);
            }
        }
    }

    private boolean markProcessed(UUID eventId) {
        return jdbc.sql("""
            INSERT INTO consumer_event_receipts(event_id, consumer_name)
            VALUES (:eventId, :consumerName)
            ON CONFLICT DO NOTHING
            """)
            .param("eventId", eventId).param("consumerName", CONSUMER_NAME)
            .update() == 1;
    }

    private static String requiredText(JsonNode data, String field) {
        var value = data == null ? null : data.get(field);
        if (value == null || value.asString().isBlank()) {
            throw new IllegalArgumentException("Missing event data field: " + field);
        }
        return value.asString();
    }

    private static String accountType(String value) {
        var normalized = value.toUpperCase();
        if (!normalized.matches("CUSTOMER|ADMIN|HOST")) throw new IllegalArgumentException("Invalid account type");
        return normalized;
    }

    private static String realm(String accountType) {
        return switch (accountType) {
            case "CUSTOMER" -> "vistay-customer";
            case "HOST" -> "vistay-host";
            case "ADMIN" -> "vistay-backoffice";
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
    }

    public record EventEnvelope(UUID eventId, String type, int version, UUID aggregateId,
        long aggregateVersion, String correlationId, String causationId, OffsetDateTime occurredAt,
        JsonNode data) {}
    private record ExpiredAccount(UUID id, String accountType) {}
    private record PendingCompletion(UUID accountId, String accountType, UUID profileId) {}
}
