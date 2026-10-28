package com.vistay.authentication.application;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.eq;

@Testcontainers
class AuthServiceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_authentication_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static JdbcClient jdbc;
    private static TransactionTemplate transactions;

    private final KeycloakAdminClient keycloak = mock(KeycloakAdminClient.class);
    private AuthService service;

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
        jdbc.sql("TRUNCATE TABLE outbox_events, provisioning_requests, identity_accounts CASCADE")
            .update();
        reset(keycloak);
        service = new AuthService(jdbc, keycloak, JsonMapper.builder().build(), transactions);
    }

    @Test
    void provisionsActiveAccountWithImmutableActorReasonAndCorrelationEvidence() {
        var actorId = UUID.randomUUID();
        var subject = UUID.randomUUID();
        var correlationId = UUID.randomUUID();
        ensureActor(actorId);
        when(keycloak.ensureBackofficeUser(
            eq("operator@vistay.vn"), eq("ViStay Operator"), eq("temporary-pass-123"), anyUuid()
        )).thenReturn(subject.toString());

        var account = service.provisionBackoffice(
            "provision-operator-1",
            actorId,
            " Operator@ViStay.vn ",
            "ViStay Operator",
            "temporary-pass-123",
            "Mở quyền vận hành ca tối",
            correlationId.toString()
        );

        assertThat(account.id()).isEqualTo(subject);
        assertThat(account.email()).isEqualTo("operator@vistay.vn");
        assertThat(account.accountType()).isEqualTo("ADMIN");
        assertThat(account.status()).isEqualTo("ACTIVE");
        var audit = jdbc.sql("""
            SELECT actor_account_id, reason, correlation_id, provisioning_mode
            FROM provisioning_requests WHERE idempotency_key = 'provision-operator-1'
            """).query(ProvisioningAudit.class).single();
        assertThat(audit.actorAccountId()).isEqualTo(actorId);
        assertThat(audit.reason()).isEqualTo("Mở quyền vận hành ca tối");
        assertThat(audit.correlationId()).isEqualTo(correlationId);
        assertThat(audit.provisioningMode()).isEqualTo("STANDARD");
        assertThat(count("outbox_events")).isEqualTo(1);
    }

    @Test
    void sameIdempotencyKeyReturnsOriginalAccountWithoutCallingKeycloakAgain() {
        var actorId = UUID.randomUUID();
        var subject = UUID.randomUUID();
        when(keycloak.ensureBackofficeUser(
            eq("checker@vistay.vn"), eq("ViStay Checker"), eq("temporary-pass-123"), anyUuid()
        )).thenReturn(subject.toString());

        var first = provision(actorId, "retry-key", "checker@vistay.vn", "ViStay Checker");
        var replay = provision(actorId, "retry-key", "checker@vistay.vn", "ViStay Checker");

        assertThat(replay).isEqualTo(first);
        verify(keycloak, times(1)).ensureBackofficeUser(
            eq("checker@vistay.vn"), eq("ViStay Checker"), eq("temporary-pass-123"), anyUuid()
        );
        assertThat(count("provisioning_requests")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(1);
    }

    @Test
    void rejectsDifferentIdempotencyKeyForAnExistingEmailWithoutDuplicateEvent() {
        var actorId = UUID.randomUUID();
        var subject = UUID.randomUUID();
        when(keycloak.ensureBackofficeUser(
            eq("duplicate@vistay.vn"), eq("First Operator"), eq("temporary-pass-123"), anyUuid()
        )).thenReturn(subject.toString());
        provision(actorId, "first-key", "duplicate@vistay.vn", "First Operator");

        assertThatThrownBy(() -> provision(
            actorId, "second-key", "DUPLICATE@vistay.vn", "Second Operator"
        ))
            .isInstanceOfSatisfying(ResponseStatusException.class, error -> {
                assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                assertThat(error.getReason()).isEqualTo("BACKOFFICE_ACCOUNT_ALREADY_EXISTS");
            });
        assertThat(count("identity_accounts")).isEqualTo(2);
        assertThat(count("provisioning_requests")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(1);
    }

    @Test
    void rejectsIdempotencyKeyReusedWithDifferentRequestData() {
        var actorId = UUID.randomUUID();
        when(keycloak.ensureBackofficeUser(
            eq("idempotent@vistay.vn"), eq("Original Name"), eq("temporary-pass-123"), anyUuid()
        )).thenReturn(UUID.randomUUID().toString());
        provision(actorId, "same-key", "idempotent@vistay.vn", "Original Name");

        assertThatThrownBy(() -> provision(
            actorId, "same-key", "idempotent@vistay.vn", "Changed Name"
        ))
            .isInstanceOfSatisfying(ResponseStatusException.class,
                error -> assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT));
    }

    @Test
    void reportsIdentityProviderUnavailabilityWithoutWritingPartialDatabaseState() {
        var actorId = UUID.randomUUID();
        ensureActor(actorId);
        when(keycloak.ensureBackofficeUser(
            eq("unavailable@vistay.vn"), eq("Unavailable User"),
            eq("temporary-pass-123"), anyUuid()
        )).thenThrow(new ResourceAccessException("Keycloak timed out"));

        assertThatThrownBy(() -> provision(
            actorId, "unavailable-key", "unavailable@vistay.vn", "Unavailable User"
        ))
            .isInstanceOfSatisfying(ResponseStatusException.class, error -> {
                assertThat(error.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
                assertThat(error.getReason()).isEqualTo("IDENTITY_PROVIDER_UNAVAILABLE");
            });
        assertThat(count("provisioning_requests")).isZero();
        assertThat(count("outbox_events")).isZero();
    }

    private AuthService.ProvisionedAccount provision(
        UUID actorId,
        String key,
        String email,
        String fullName
    ) {
        ensureActor(actorId);
        return service.provisionBackoffice(
            key,
            actorId,
            email,
            fullName,
            "temporary-pass-123",
            "Account required for test operations",
            UUID.randomUUID().toString()
        );
    }

    private long count(String table) {
        return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
    }

    private void ensureActor(UUID actorId) {
        jdbc.sql("""
            INSERT INTO identity_accounts(id, realm, subject, account_type, email, status)
            VALUES (:id, 'vistay-backoffice', :subject, 'ADMIN', :email, 'ACTIVE')
            ON CONFLICT (id) DO NOTHING
            """)
            .param("id", actorId)
            .param("subject", actorId.toString())
            .param("email", "actor+" + actorId + "@vistay.test")
            .update();
    }

    private static UUID anyUuid() {
        return org.mockito.ArgumentMatchers.any(UUID.class);
    }

    record ProvisioningAudit(
        UUID actorAccountId,
        String reason,
        UUID correlationId,
        String provisioningMode
    ) {}
}
