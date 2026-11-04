package com.vistay.authentication.adapter.out.keycloak;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withCreatedEntity;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class KeycloakAdminClientTest {
    @Test
    void createsBootstrapAdministratorAsVerifiedWithMandatoryPasswordChange() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = new KeycloakAdminClient(
            builder,
            "http://identity.test",
            "vistay-backoffice",
            "vistay-auth-facade",
            "test-secret"
        );
        var subject = UUID.randomUUID();

        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/realms/vistay-backoffice/protocol/openid-connect/token"))
            .andExpect(method(HttpMethod.POST))
            .andRespond(withSuccess("{\"access_token\":\"service-token\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        server.expect(once(), request -> {
                assertThat(request.getURI().getPath())
                    .isEqualTo("/admin/realms/vistay-backoffice/users");
                assertThat(request.getURI().getQuery())
                    .contains("email=admin@vistay.test", "exact=true", "max=2");
            })
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/users"))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().json("""
                {
                  "username": "admin@vistay.test",
                  "email": "admin@vistay.test",
                  "enabled": true,
                  "emailVerified": true,
                  "requiredActions": ["UPDATE_PASSWORD"],
                  "credentials": [{"type":"password","value":"temporary-password","temporary":true}],
                  "attributes": {"vistay_account_type":["ADMIN"]}
                }
                """, JsonCompareMode.LENIENT))
            .andRespond(withCreatedEntity(URI.create(
                "http://identity.test/admin/realms/vistay-backoffice/users/" + subject
            )));

        var actual = client.ensureBackofficeUser(
            "admin@vistay.test",
            "ViStay Administrator",
            "temporary-password",
            UUID.randomUUID()
        );

        assertThat(actual).isEqualTo(subject.toString());
        server.verify();
    }

    @Test
    void reusesExistingKeycloakUserWhenRepairingAPartialProvisioningAttempt() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = new KeycloakAdminClient(
            builder,
            "http://identity.test",
            "vistay-backoffice",
            "vistay-auth-facade",
            "test-secret"
        );
        var subject = UUID.randomUUID();

        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/realms/vistay-backoffice/protocol/openid-connect/token"))
            .andExpect(method(HttpMethod.POST))
            .andRespond(withSuccess("{\"access_token\":\"service-token\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/users"))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("[{\"id\":\"" + subject + "\"}]", MediaType.APPLICATION_JSON));

        var actual = client.ensureBackofficeUser(
            "repair@vistay.test",
            "Repair Operator",
            "temporary-password",
            UUID.randomUUID()
        );

        assertThat(actual).isEqualTo(subject.toString());
        server.verify();
    }

    @Test
    void listsActiveSessionsFromKeycloakWithoutPersistingTokens() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = client(builder);
        var accountId = UUID.randomUUID();

        expectServiceToken(server);
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/users/" + accountId + "/sessions"))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("""
                [{
                  "id":"session-1",
                  "ipAddress":"10.0.0.8",
                  "start":1761670800000,
                  "lastAccess":1761670860000,
                  "clients":{"vistay-backoffice-web":"ViStay Backoffice Web"}
                }]
                """, MediaType.APPLICATION_JSON));

        var sessions = client.listUserSessions(accountId);

        assertThat(sessions).hasSize(1);
        assertThat(sessions.getFirst().id()).isEqualTo("session-1");
        assertThat(sessions.getFirst().startedAt()).isEqualTo(Instant.ofEpochMilli(1761670800000L));
        assertThat(sessions.getFirst().clients()).containsKey("vistay-backoffice-web");
        server.verify();
    }

    @Test
    void revokesOneSpecificKeycloakSession() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = client(builder);

        expectServiceToken(server);
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/sessions/session-1"))
            .andExpect(method(HttpMethod.DELETE))
            .andRespond(withSuccess());

        client.revokeSession("session-1");

        server.verify();
    }

    private static KeycloakAdminClient client(RestClient.Builder builder) {
        return new KeycloakAdminClient(
            builder,
            "http://identity.test",
            "vistay-backoffice",
            "vistay-auth-facade",
            "test-secret"
        );
    }

    private static void expectServiceToken(MockRestServiceServer server) {
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/realms/vistay-backoffice/protocol/openid-connect/token"))
            .andExpect(method(HttpMethod.POST))
            .andRespond(withSuccess("{\"access_token\":\"service-token\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
    }
}
