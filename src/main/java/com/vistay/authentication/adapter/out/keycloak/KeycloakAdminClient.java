package com.vistay.authentication.adapter.out.keycloak;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Component
public class KeycloakAdminClient {
    private final RestClient http;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private volatile CachedToken cachedToken;

    public KeycloakAdminClient(
        RestClient.Builder builder,
        @Value("${vistay.keycloak.base-url}") String baseUrl,
        @Value("${vistay.keycloak.backoffice-realm}") String realm,
        @Value("${vistay.keycloak.admin-client-id}") String clientId,
        @Value("${vistay.keycloak.admin-client-secret}") String clientSecret
    ) {
        this.http = builder.baseUrl(baseUrl).build();
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String ensureBackofficeUser(
        String email,
        String fullName,
        String temporaryPassword,
        UUID provisioningReference
    ) {
        var existing = findExactByEmail(email);
        if (existing != null) {
            return existing;
        }

        var name = splitName(fullName);
        var representation = new UserRepresentation(
            email,
            email,
            name.firstName(),
            name.lastName(),
            true,
            false,
            List.of("VERIFY_EMAIL"),
            List.of(new CredentialRepresentation("password", temporaryPassword, true)),
            Map.of(
                "vistay_account_type", List.of("ADMIN"),
                "vistay_provisioning_reference", List.of(provisioningReference.toString())
            )
        );

        try {
            var response = http.post()
                .uri("/admin/realms/{realm}/users", realm)
                .headers(headers -> headers.setBearerAuth(accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .body(representation)
                .retrieve()
                .toBodilessEntity();
            return subjectFromLocation(response.getHeaders().getLocation());
        } catch (HttpClientErrorException.Conflict duplicate) {
            var concurrent = findExactByEmail(email);
            if (concurrent != null) {
                return concurrent;
            }
            throw duplicate;
        }
    }

    private String findExactByEmail(String email) {
        var users = http.get()
            .uri(uri -> uri
                .path("/admin/realms/{realm}/users")
                .queryParam("email", email)
                .queryParam("exact", true)
                .queryParam("max", 2)
                .build(realm))
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .body(UserSummary[].class);
        if (users == null || users.length == 0) {
            return null;
        }
        if (users.length > 1) {
            throw new IllegalStateException("Keycloak returned multiple exact users for one email");
        }
        return users[0].id();
    }

    private String accessToken() {
        var snapshot = cachedToken;
        if (snapshot != null && snapshot.expiresAt().isAfter(Instant.now().plusSeconds(15))) {
            return snapshot.value();
        }
        synchronized (this) {
            snapshot = cachedToken;
            if (snapshot != null && snapshot.expiresAt().isAfter(Instant.now().plusSeconds(15))) {
                return snapshot.value();
            }
            var form = new LinkedMultiValueMap<String, String>();
            form.add("grant_type", "client_credentials");
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);
            var response = http.post()
                .uri("/realms/{realm}/protocol/openid-connect/token", realm)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(TokenResponse.class);
            if (response == null || response.accessToken() == null) {
                throw new IllegalStateException("Keycloak did not return a service-account token");
            }
            cachedToken = new CachedToken(
                response.accessToken(),
                Instant.now().plusSeconds(Math.max(response.expiresIn(), 30))
            );
            return cachedToken.value();
        }
    }

    private static String subjectFromLocation(URI location) {
        if (location == null || location.getPath() == null) {
            throw new IllegalStateException("Keycloak create-user response has no Location header");
        }
        var path = location.getPath();
        var separator = path.lastIndexOf('/');
        if (separator < 0 || separator == path.length() - 1) {
            throw new IllegalStateException("Keycloak create-user Location is invalid");
        }
        return path.substring(separator + 1);
    }

    private static Name splitName(String fullName) {
        var normalized = fullName.trim();
        var separator = normalized.lastIndexOf(' ');
        return separator < 0
            ? new Name(normalized, "")
            : new Name(normalized.substring(0, separator), normalized.substring(separator + 1));
    }

    private record Name(String firstName, String lastName) {}
    private record CachedToken(String value, Instant expiresAt) {}
    private record TokenResponse(
        @com.fasterxml.jackson.annotation.JsonProperty("access_token") String accessToken,
        @com.fasterxml.jackson.annotation.JsonProperty("expires_in") long expiresIn
    ) {}
    private record UserSummary(String id) {}
    private record CredentialRepresentation(String type, String value, boolean temporary) {}
    private record UserRepresentation(
        String username,
        String email,
        String firstName,
        String lastName,
        boolean enabled,
        boolean emailVerified,
        List<String> requiredActions,
        List<CredentialRepresentation> credentials,
        Map<String, List<String>> attributes
    ) {}
}
