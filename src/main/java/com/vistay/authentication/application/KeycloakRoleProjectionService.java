package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

/** Projects User-owned role assignments into Keycloak client roles. */
@Service
public class KeycloakRoleProjectionService {
    private static final Logger log = LoggerFactory.getLogger(KeycloakRoleProjectionService.class);
    private final AuthorizationClient authorization;
    private final KeycloakAdminClient keycloak;
    private final ObjectMapper json;
    private final JdbcClient jdbc;

    public KeycloakRoleProjectionService(
        AuthorizationClient authorization,
        KeycloakAdminClient keycloak,
        ObjectMapper json,
        JdbcClient jdbc
    ) {
        this.authorization = authorization;
        this.keycloak = keycloak;
        this.json = json;
        this.jdbc = jdbc;
    }

    @KafkaListener(
        topics = "${vistay.topics.authorization-changed:vistay.user.authorization-changed.v1}",
        groupId = "${spring.application.name}-keycloak-role-projection"
    )
    public void authorizationChanged(String rawEnvelope) {
        var data = json.readTree(rawEnvelope).get("data");
        if (data == null || !"ADMIN".equals(data.get("accountType").asString())) return;
        var accountId = UUID.fromString(data.get("accountId").asString());
        var version = data.get("authorizationVersion").asLong();
        authorization.invalidate(accountId, version);
        reconcile(accountId);
    }

    @Scheduled(fixedDelayString = "${vistay.authorization.keycloak-reconcile-delay-ms:300000}")
    public void reconcileExistingUsers() {
        var accountIds = jdbc.sql("""
                SELECT id FROM identity_accounts
                WHERE realm = 'vistay-backoffice' AND account_type = 'ADMIN' AND status = 'ACTIVE'
                ORDER BY updated_at, id LIMIT 100
                """).query(UUID.class).list();
        for (var accountId : accountIds) {
            try {
                reconcile(accountId);
            } catch (RuntimeException failure) {
                log.warn("Keycloak role reconciliation failed for accountId={}", accountId, failure);
            }
        }
    }

    private void reconcile(UUID accountId) {
        var snapshot = authorization.get(accountId);
        var desiredRoles = snapshot.active() ? snapshot.roles() : java.util.Set.<String>of();
        if (snapshot.active() && snapshot.profileId() != null && !snapshot.profileId().isBlank()) {
            keycloak.setBackofficeProfileId(accountId, snapshot.profileId());
        }
        var changed = keycloak.reconcileBackofficeRoles(accountId, desiredRoles);
        if (changed || !snapshot.active()) {
            // Revokes refresh tokens/sessions immediately. Existing access
            // tokens remain bounded by the realm's five-minute lifespan.
            keycloak.logoutUser(accountId);
        }
    }
}
