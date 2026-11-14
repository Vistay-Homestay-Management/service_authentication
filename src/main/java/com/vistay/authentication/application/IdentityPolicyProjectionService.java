package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import java.time.OffsetDateTime;
import java.util.Locale;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class IdentityPolicyProjectionService {
    public static final String POLICY_CHANGED = "vistay.user.identity-policy-changed";
    private static final String CONSUMER_NAME = "authentication-identity-policy-v1";

    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final KeycloakAdminClient keycloak;

    public IdentityPolicyProjectionService(
        JdbcClient jdbc,
        ObjectMapper json,
        KeycloakAdminClient keycloak
    ) {
        this.jdbc = jdbc;
        this.json = json;
        this.keycloak = keycloak;
    }

    @KafkaListener(
        topics = "${vistay.topics.identity-policy-changed:vistay.user.identity-policy-changed.v1}",
        groupId = "${spring.application.name}-identity-policy-v1"
    )
    @Transactional
    public void consume(String rawEnvelope) throws Exception {
        var event = json.readValue(rawEnvelope, EventEnvelope.class);
        if (event.version() != 1 || !POLICY_CHANGED.equals(event.type())) {
            throw new IllegalArgumentException("Unsupported identity policy event");
        }
        if (!markProcessed(event.eventId())) return;

        var accountType = accountType(requiredText(event.data(), "accountType"));
        var policyVersion = requiredPositiveLong(event.data(), "policyVersion");
        var registrationEnabled = requiredBoolean(event.data(), "registrationEnabled");
        var linkMode = linkMode(requiredText(event.data(), "linkMode"));
        var current = jdbc.sql("""
            SELECT policy_version FROM identity_policy_projection
            WHERE account_type = :accountType
            FOR UPDATE
            """).param("accountType", accountType).query(Long.class).optional().orElse(0L);
        if (policyVersion <= current) return;

        keycloak.setRegistrationEnabled(accountType, registrationEnabled);
        jdbc.sql("""
            INSERT INTO identity_policy_projection(
                account_type, policy_version, registration_enabled,
                link_mode, source_event_id, projected_at
            ) VALUES (
                :accountType, :policyVersion, :registrationEnabled,
                :linkMode, :eventId, now()
            )
            ON CONFLICT (account_type) DO UPDATE
            SET policy_version = EXCLUDED.policy_version,
                registration_enabled = EXCLUDED.registration_enabled,
                link_mode = EXCLUDED.link_mode,
                source_event_id = EXCLUDED.source_event_id,
                projected_at = now()
            WHERE identity_policy_projection.policy_version < EXCLUDED.policy_version
            """).param("accountType", accountType).param("policyVersion", policyVersion)
            .param("registrationEnabled", registrationEnabled).param("linkMode", linkMode)
            .param("eventId", event.eventId()).update();
    }

    private boolean markProcessed(UUID eventId) {
        return jdbc.sql("""
            INSERT INTO consumer_event_receipts(event_id, consumer_name)
            VALUES (:eventId, :consumerName)
            ON CONFLICT DO NOTHING
            """).param("eventId", eventId).param("consumerName", CONSUMER_NAME).update() == 1;
    }

    private static String requiredText(JsonNode data, String field) {
        var value = data == null ? null : data.get(field);
        if (value == null || value.isNull() || value.asString().isBlank()) {
            throw new IllegalArgumentException("Missing identity policy field: " + field);
        }
        return value.asString();
    }

    private static boolean requiredBoolean(JsonNode data, String field) {
        var value = data == null ? null : data.get(field);
        if (value == null || value.isNull() || !value.isBoolean()) {
            throw new IllegalArgumentException("Missing boolean identity policy field: " + field);
        }
        return value.asBoolean();
    }

    private static long requiredPositiveLong(JsonNode data, String field) {
        var value = data == null ? null : data.get(field);
        if (value == null || !value.isNumber() || value.asLong() < 1) {
            throw new IllegalArgumentException("Invalid identity policy version");
        }
        return value.asLong();
    }

    private static String accountType(String value) {
        var normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("CUSTOMER|HOST|ADMIN")) throw new IllegalArgumentException("Invalid account type");
        return normalized;
    }

    private static String linkMode(String value) {
        var normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("AUTO_LINK|REQUIRE_APPROVAL")) throw new IllegalArgumentException("Invalid link mode");
        return normalized;
    }

    public record EventEnvelope(UUID eventId, String type, int version, UUID aggregateId,
        long aggregateVersion, String correlationId, String causationId, OffsetDateTime occurredAt,
        JsonNode data) {}
}
