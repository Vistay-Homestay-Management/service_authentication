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
    void provisionsHostWithoutLocalCredentialsAndObservesActivationState() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = hostClient(builder);
        var invitationId = UUID.randomUUID();
        var subject = UUID.randomUUID();

        expectServiceToken(server);
        server.expect(once(), request -> {
                assertThat(request.getURI().getPath())
                    .isEqualTo("/admin/realms/vistay-host/users");
                assertThat(request.getURI().getQuery())
                    .contains("email=host@vistay.test", "exact=true", "max=2");
            })
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-host/users"))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().json("""
                {
                  "username": "host@vistay.test",
                  "email": "host@vistay.test",
                  "firstName": "Host",
                  "lastName": "Operator",
                  "enabled": true,
                  "emailVerified": false,
                  "requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
                  "credentials": [],
                  "attributes": {
                    "vistay_account_type": ["HOST"],
                    "vistay_invitation_id": ["%s"],
                    "phone": ["+84900000000"]
                  }
                }
                """.formatted(invitationId), JsonCompareMode.LENIENT))
            .andRespond(withCreatedEntity(URI.create(
                "http://identity.test/admin/realms/vistay-host/users/" + subject
            )));
        server.expect(once(), request -> {
                assertThat(request.getURI().getPath()).isEqualTo(
                    "/admin/realms/vistay-host/users/" + subject + "/execute-actions-email");
                assertThat(request.getURI().getQuery())
                    .contains("lifespan=900", "client_id=vistay-host-web",
                        "redirect_uri=http://host.localhost/oidc/callback");
            })
            .andExpect(method(HttpMethod.PUT))
            .andExpect(content().json("[\"VERIFY_EMAIL\",\"UPDATE_PASSWORD\"]"))
            .andRespond(withSuccess());
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-host/users/" + subject))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("""
                {
                  "id": "%s",
                  "emailVerified": true,
                  "enabled": true,
                  "requiredActions": []
                }
                """.formatted(subject), MediaType.APPLICATION_JSON));

        assertThat(client.ensureHostUser(
            "host@vistay.test", "Host Operator", "+84900000000", invitationId
        ).subject()).isEqualTo(subject.toString());
        client.sendHostActivationEmail(subject.toString());
        var activation = client.hostActivationState(subject.toString());

        assertThat(activation.emailVerified()).isTrue();
        assertThat(activation.enabled()).isTrue();
        assertThat(activation.requiredActions()).isEmpty();
        server.verify();
    }

    @Test
    void projectsDynamicApiRoleIntoEveryBackofficeTokenClientScope() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = client(builder);
        var accountId = UUID.randomUUID();
        var apiId = "api-client-uuid";
        var roleId = "dynamic-role-uuid";

        expectServiceToken(server);
        expectClientLookup(server, "vistay-backoffice-api", apiId);
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/clients/" + apiId + "/roles"))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("""
                [{"id":"%s","name":"CUSTOM_OPERATIONS","description":"Dynamic role"}]
                """.formatted(roleId), MediaType.APPLICATION_JSON));

        for (var consumer : List.of(
            "vistay-backoffice-web",
            "vistay-backoffice-mobile",
            "vistay-backoffice-postman"
        )) {
            var consumerId = consumer + "-uuid";
            expectClientLookup(server, consumer, consumerId);
            server.expect(once(), request -> assertThat(request.getURI().getPath()).isEqualTo(
                    "/admin/realms/vistay-backoffice/clients/" + consumerId
                        + "/scope-mappings/clients/" + apiId))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
            server.expect(once(), request -> assertThat(request.getURI().getPath()).isEqualTo(
                    "/admin/realms/vistay-backoffice/clients/" + consumerId
                        + "/scope-mappings/clients/" + apiId))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().json("""
                    [{"id":"%s","name":"CUSTOM_OPERATIONS","description":"Dynamic role"}]
                    """.formatted(roleId), JsonCompareMode.STRICT))
                .andRespond(withSuccess());
        }

        server.expect(once(), request -> assertThat(request.getURI().getPath()).isEqualTo(
                "/admin/realms/vistay-backoffice/users/" + accountId
                    + "/role-mappings/clients/" + apiId))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(once(), request -> assertThat(request.getURI().getPath()).isEqualTo(
                "/admin/realms/vistay-backoffice/users/" + accountId
                    + "/role-mappings/clients/" + apiId))
            .andExpect(method(HttpMethod.POST))
            .andRespond(withSuccess());

        assertThat(client.reconcileBackofficeRoles(accountId, java.util.Set.of("CUSTOM_OPERATIONS")))
            .isTrue();
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

    @Test
    void preservesEmailAndRequiredActionsWhenProjectingTheProfileId() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var client = client(builder);
        var accountId = UUID.randomUUID();
        var profileId = UUID.randomUUID().toString();

        expectServiceToken(server);
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/users/" + accountId))
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("""
                {
                  "id":"%s",
                  "username":"admin@vistay.local",
                  "email":"admin@example.com",
                  "emailVerified":false,
                  "enabled":true,
                  "requiredActions":["VERIFY_EMAIL"],
                  "attributes":{"vistay_account_type":["ADMIN"]}
                }
                """.formatted(accountId), MediaType.APPLICATION_JSON));
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/admin/realms/vistay-backoffice/users/" + accountId))
            .andExpect(method(HttpMethod.PUT))
            .andExpect(content().json("""
                {
                  "id":"%s",
                  "username":"admin@vistay.local",
                  "email":"admin@example.com",
                  "emailVerified":false,
                  "enabled":true,
                  "requiredActions":["VERIFY_EMAIL"],
                  "attributes":{
                    "vistay_account_type":["ADMIN"],
                    "vistay_profile_id":["%s"]
                  }
                }
                """.formatted(accountId, profileId), JsonCompareMode.STRICT))
            .andRespond(withSuccess());

        client.setBackofficeProfileId(accountId, profileId);

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

    private static KeycloakAdminClient hostClient(RestClient.Builder builder) {
        return new KeycloakAdminClient(
            builder,
            "http://identity.test",
            "vistay-backoffice",
            "vistay-auth-facade",
            "test-secret",
            "vistay-host",
            "vistay-host-web",
            900,
            "http://host.localhost/oidc/callback"
        );
    }

    private static void expectServiceToken(MockRestServiceServer server) {
        server.expect(once(), request -> assertThat(request.getURI().getPath())
                .isEqualTo("/realms/vistay-backoffice/protocol/openid-connect/token"))
            .andExpect(method(HttpMethod.POST))
            .andRespond(withSuccess("{\"access_token\":\"service-token\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
    }

    private static void expectClientLookup(
        MockRestServiceServer server,
        String clientId,
        String clientUuid
    ) {
        server.expect(once(), request -> {
                assertThat(request.getURI().getPath())
                    .isEqualTo("/admin/realms/vistay-backoffice/clients");
                assertThat(request.getURI().getQuery()).isEqualTo("clientId=" + clientId);
            })
            .andExpect(method(HttpMethod.GET))
            .andRespond(withSuccess("""
                [{"id":"%s","clientId":"%s"}]
                """.formatted(clientUuid, clientId), MediaType.APPLICATION_JSON));
    }
}
