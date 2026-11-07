package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.HostActivationState;
import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.HostIdentity;
import java.util.List;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Testcontainers
class HostInvitationServiceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_authentication_host_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static JdbcClient jdbc;
    private static TransactionTemplate transactions;
    private final KeycloakAdminClient keycloak = mock(KeycloakAdminClient.class);
    private HostInvitationService service;

    @BeforeAll
    static void migrate() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(),
            POSTGRES.getPassword()
        );
        Flyway.configure()
            .dataSource(dataSource)
            .defaultSchema("app")
            .schemas("app")
            .locations("classpath:db/migration")
            .load()
            .migrate();
        jdbc = JdbcClient.create(dataSource);
        transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
    }

    @BeforeEach
    void setUp() {
        jdbc.sql("TRUNCATE TABLE outbox_events, host_invitation_audit, host_invitation_resends, host_invitations, identity_accounts CASCADE")
            .update();
        reset(keycloak);
        service = new HostInvitationService(jdbc, keycloak, JsonMapper.builder().build(), transactions);
    }

    @Test
    void issuesHostInvitationWithRequiredActionsAndRedactedEvent() {
        var actor = actor();
        var subject = UUID.randomUUID();
        var propertyId = UUID.randomUUID();
        var branchId = UUID.randomUUID();
        when(keycloak.ensureHostUser(
            eq("host@vistay.vn"), eq("ViStay Host"), eq("+84900000000"), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));

        var result = service.invite(
            "host-invitation-key-01", actor, " Host@ViStay.vn ", "ViStay Host", "+84900000000",
            "Primary signatory for property operations", "HOST", propertyId, branchId,
            UUID.randomUUID().toString()
        );

        assertThat(result.state()).isEqualTo("ACTIONS_PENDING");
        assertThat(result.aggregateVersion()).isEqualTo(2);
        assertThat(result.replayed()).isFalse();
        verify(keycloak).sendHostActivationEmail(subject.toString());
        assertThat(count("host_invitations")).isEqualTo(1);
        assertThat(count("host_invitation_audit")).isEqualTo(2);
        assertThat(count("outbox_events")).isEqualTo(1);
        var payload = jdbc.sql("SELECT payload::text FROM outbox_events").query(String.class).single();
        assertThat(payload).contains("contactReferenceHash", propertyId.toString(), branchId.toString());
        assertThat(payload).doesNotContain("host@vistay.vn", "ViStay Host", "+84900000000");
    }

    @Test
    void replaysInvitationWithoutCreatingIdentityOrSendingAnotherEmail() {
        var actor = actor();
        var subject = UUID.randomUUID();
        var propertyId = invitationProperty();
        var branchId = invitationBranch();
        when(keycloak.ensureHostUser(
            eq("replay@vistay.vn"), eq("Replay Host"), isNull(), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));

        var first = service.invite(
            "host-invitation-key-02", actor, "replay@vistay.vn", "Replay Host", null,
            "Replay-safe host invitation", "HOST", propertyId, branchId, null
        );
        var replay = service.invite(
            "host-invitation-key-02", actor, "REPLAY@vistay.vn", "Replay Host", null,
            "Replay-safe host invitation", "HOST", propertyId, branchId, null
        );

        assertThat(replay.invitationId()).isEqualTo(first.invitationId());
        assertThat(replay.replayed()).isTrue();
        verify(keycloak, times(1)).ensureHostUser(
            eq("replay@vistay.vn"), eq("Replay Host"), isNull(), any(UUID.class)
        );
        verify(keycloak, times(1)).sendHostActivationEmail(subject.toString());
        assertThat(count("host_invitations")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(1);
    }

    @Test
    void rejectsDifferentBodyUnderSameIdempotencyKeyAndDuplicateEmailUnderAnotherKey() {
        var actor = actor();
        var subject = UUID.randomUUID();
        when(keycloak.ensureHostUser(
            eq("duplicate@vistay.vn"), eq("First Host"), isNull(), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));
        service.invite(
            "host-invitation-key-03", actor, "duplicate@vistay.vn", "First Host", null,
            "First host invitation", "HOST", invitationProperty(), invitationBranch(), null
        );

        assertThatThrownBy(() -> service.invite(
            "host-invitation-key-03", actor, "duplicate@vistay.vn", "Changed Host", null,
            "First host invitation", "HOST", invitationProperty(), invitationBranch(), null
        )).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
            assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(error.getReason()).isEqualTo("HOST_IDEMPOTENCY_CONFLICT");
        });

        assertThatThrownBy(() -> service.invite(
            "host-invitation-key-04", actor, "DUPLICATE@vistay.vn", "Second Host", null,
            "Second host invitation", "HOST", invitationProperty(), invitationBranch(), null
        )).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
            assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(error.getReason()).isEqualTo("HOST_EMAIL_ALREADY_INVITED");
        });
        assertThat(count("host_invitations")).isEqualTo(1);
    }

    @Test
    void retriesUncertainActionEmailWithoutCreatingAnotherUser() {
        var actor = actor();
        var subject = UUID.randomUUID();
        when(keycloak.ensureHostUser(
            eq("uncertain@vistay.vn"), eq("Uncertain Host"), isNull(), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));
        doThrow(new ResourceAccessException("Mail dispatch unavailable"))
            .when(keycloak).sendHostActivationEmail(subject.toString());

        assertThatThrownBy(() -> service.invite(
            "host-invitation-key-05", actor, "uncertain@vistay.vn", "Uncertain Host", null,
            "Retry the action email safely", "HOST", invitationProperty(), invitationBranch(), null
        )).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
            assertThat(error.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(error.getReason()).isEqualTo("HOST_INVITATION_DISPATCH_UNAVAILABLE");
        });
        assertThat(jdbc.sql("SELECT action_dispatch_status FROM host_invitations")
            .query(String.class).single()).isEqualTo("RETRY_REQUIRED");

        org.mockito.Mockito.doNothing().when(keycloak).sendHostActivationEmail(subject.toString());
        var retried = service.invite(
            "host-invitation-key-05", actor, "uncertain@vistay.vn", "Uncertain Host", null,
            "Retry the action email safely", "HOST", invitationProperty(), invitationBranch(), null
        );
        assertThat(retried.state()).isEqualTo("ACTIONS_PENDING");
        verify(keycloak, times(2)).sendHostActivationEmail(subject.toString());
        assertThat(count("host_invitations")).isEqualTo(1);
    }

    @Test
    void resendsIdempotentlyAndActivatesOnlyAfterKeycloakActionsComplete() {
        var actor = actor();
        var subject = UUID.randomUUID();
        when(keycloak.ensureHostUser(
            eq("activate@vistay.vn"), eq("Activate Host"), isNull(), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));
        var invitation = service.invite(
            "host-invitation-key-06", actor, "activate@vistay.vn", "Activate Host", null,
            "Activate host after verified email", "HOST", invitationProperty(), invitationBranch(), null
        );

        var resent = service.resend(
            "host-resend-key-01", actor, invitation.invitationId(),
            "Resend the host activation email", null
        );
        var resendReplay = service.resend(
            "host-resend-key-01", actor, invitation.invitationId(),
            "Resend the host activation email", null
        );
        assertThat(resent.state()).isEqualTo("ACTIONS_PENDING");
        assertThat(resendReplay.replayed()).isTrue();
        verify(keycloak, times(2)).sendHostActivationEmail(subject.toString());
        assertThat(count("host_invitation_resends")).isEqualTo(1);

        when(keycloak.hostActivationState(subject.toString()))
            .thenReturn(new HostActivationState(true, true, List.of()));
        var activated = service.activate(
            invitation.invitationId(), subject.toString(), resent.aggregateVersion(), null
        );
        var activationReplay = service.activate(
            invitation.invitationId(), subject.toString(), activated.aggregateVersion(), null
        );
        assertThat(activated.state()).isEqualTo("ACTIVE");
        assertThat(activated.authorizationVersion()).isEqualTo(1);
        assertThat(activationReplay.replayed()).isTrue();
        verify(keycloak, times(1)).hostActivationState(subject.toString());
        assertThat(count("outbox_events")).isEqualTo(2);
        assertThat(jdbc.sql("SELECT count(*) FROM host_invitation_audit WHERE action = 'INVITATION_ACTIVATED'")
            .query(Long.class).single()).isEqualTo(1);
    }

    @Test
    void doesNotActivateWhileEmailOrRequiredActionsRemain() {
        var actor = actor();
        var subject = UUID.randomUUID();
        when(keycloak.ensureHostUser(
            eq("pending@vistay.vn"), eq("Pending Host"), isNull(), any(UUID.class)
        )).thenReturn(new HostIdentity(subject.toString()));
        var invitation = service.invite(
            "host-invitation-key-07", actor, "pending@vistay.vn", "Pending Host", null,
            "Wait for Host required actions", "HOST", invitationProperty(), invitationBranch(), null
        );
        when(keycloak.hostActivationState(subject.toString()))
            .thenReturn(new HostActivationState(false, true, List.of("VERIFY_EMAIL")));

        assertThatThrownBy(() -> service.activate(
            invitation.invitationId(), subject.toString(), invitation.aggregateVersion(), null
        )).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
            assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(error.getReason()).isEqualTo("HOST_ACTIVATION_ACTIONS_PENDING");
        });
        assertThat(count("outbox_events")).isEqualTo(1);
        assertThat(jdbc.sql("SELECT state FROM host_invitations")
            .query(String.class).single()).isEqualTo("ACTIONS_PENDING");
    }

    private UUID actor() {
        var actorId = UUID.randomUUID();
        jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, 'vistay-backoffice', :subject, 'ADMIN', :email, 'ACTIVE')
            """)
            .param("id", actorId).param("subject", actorId.toString())
            .param("email", "actor+" + actorId + "@vistay.test").update();
        return actorId;
    }

    private long count(String table) {
        return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
    }

    private static UUID invitationProperty() {
        return UUID.nameUUIDFromBytes("property-for-host-test".getBytes());
    }

    private static UUID invitationBranch() {
        return UUID.nameUUIDFromBytes("branch-for-host-test".getBytes());
    }
}
