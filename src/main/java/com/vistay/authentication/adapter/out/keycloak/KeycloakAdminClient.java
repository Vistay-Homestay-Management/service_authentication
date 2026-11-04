package com.vistay.authentication.adapter.out.keycloak;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
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
    private final String hostRealm;
    private final String hostClientId;
    private final int hostActionLifespanSeconds;
    private final String hostRedirectUri;
    private volatile CachedToken cachedToken;

    @Autowired
    public KeycloakAdminClient(
        RestClient.Builder builder,
        @Value("${vistay.keycloak.base-url}") String baseUrl,
        @Value("${vistay.keycloak.backoffice-realm}") String realm,
        @Value("${vistay.keycloak.admin-client-id}") String clientId,
        @Value("${vistay.keycloak.admin-client-secret}") String clientSecret,
        @Value("${vistay.keycloak.host-realm:vistay-host}") String hostRealm,
        @Value("${vistay.keycloak.host-client-id:vistay-host-web}") String hostClientId,
        @Value("${vistay.keycloak.host-action-lifespan-seconds:900}") int hostActionLifespanSeconds,
        @Value("${vistay.keycloak.host-redirect-uri:http://host.localhost/oidc/callback}") String hostRedirectUri
    ) {
        this.http = builder.baseUrl(baseUrl).build();
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.hostRealm = hostRealm;
        this.hostClientId = hostClientId;
        this.hostActionLifespanSeconds = hostActionLifespanSeconds;
        this.hostRedirectUri = hostRedirectUri;
    }

    public KeycloakAdminClient(
        RestClient.Builder builder,
        String baseUrl,
        String realm,
        String clientId,
        String clientSecret
    ) {
        this(builder, baseUrl, realm, clientId, clientSecret,
            "vistay-host", "vistay-host-web", 900,
            "http://host.localhost/oidc/callback");
    }

    public String ensureBackofficeUser(
        String email,
        String fullName,
        String temporaryPassword,
        UUID provisioningReference
    ) {
        var existing = findExactUserByEmail(realm, email);
        if (existing != null) {
            return existing.id();
        }

        var name = splitName(fullName);
        var representation = new UserRepresentation(
            email,
            email,
            name.firstName(),
            name.lastName(),
            true,
            true,
            List.of("UPDATE_PASSWORD"),
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
            var concurrent = findExactUserByEmail(realm, email);
            if (concurrent != null) {
                return concurrent.id();
            }
            throw duplicate;
        }
    }

    public HostIdentity ensureHostUser(
        String email,
        String fullName,
        String phone,
        UUID invitationId
    ) {
        var existing = findExactUserByEmail(hostRealm, email);
        if (existing != null) {
            return verifyHostIdentity(existing, invitationId);
        }

        var name = splitName(fullName);
        var attributes = new LinkedHashMap<String, List<String>>();
        attributes.put("vistay_account_type", List.of("HOST"));
        attributes.put("vistay_invitation_id", List.of(invitationId.toString()));
        if (phone != null && !phone.isBlank()) {
            attributes.put("phone", List.of(phone));
        }
        var representation = new UserRepresentation(
            email,
            email,
            name.firstName(),
            name.lastName(),
            true,
            false,
            List.of("VERIFY_EMAIL", "UPDATE_PASSWORD"),
            List.of(),
            attributes
        );

        try {
            var response = http.post()
                .uri("/admin/realms/{realm}/users", hostRealm)
                .headers(headers -> headers.setBearerAuth(accessToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .body(representation)
                .retrieve()
                .toBodilessEntity();
            return new HostIdentity(subjectFromLocation(response.getHeaders().getLocation()));
        } catch (HttpClientErrorException.Conflict duplicate) {
            var concurrent = findExactUserByEmail(hostRealm, email);
            if (concurrent != null) {
                return verifyHostIdentity(concurrent, invitationId);
            }
            throw duplicate;
        }
    }

    public void sendHostActivationEmail(String subject) {
        http.put()
            .uri(uri -> uri
                .path("/admin/realms/{realm}/users/{userId}/execute-actions-email")
                .queryParam("lifespan", hostActionLifespanSeconds)
                .queryParam("client_id", hostClientId)
                .queryParam("redirect_uri", hostRedirectUri)
                .build(hostRealm, subject))
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(List.of("VERIFY_EMAIL", "UPDATE_PASSWORD"))
            .retrieve()
            .toBodilessEntity();
    }

    public HostActivationState hostActivationState(String subject) {
        var user = http.get()
            .uri("/admin/realms/{realm}/users/{userId}", hostRealm, subject)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .body(UserSummary.class);
        if (user == null) {
            throw new IllegalStateException("Keycloak returned no Host identity state");
        }
        return new HostActivationState(
            Boolean.TRUE.equals(user.emailVerified()),
            Boolean.TRUE.equals(user.enabled()),
            user.requiredActions() == null ? List.of() : List.copyOf(user.requiredActions())
        );
    }

    public List<ActiveSession> listUserSessions(UUID accountId) {
        var sessions = http.get()
            .uri("/admin/realms/{realm}/users/{userId}/sessions", realm, accountId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .body(UserSessionRepresentation[].class);
        if (sessions == null) {
            return List.of();
        }
        return Arrays.stream(sessions)
            .map(session -> new ActiveSession(
                session.id(),
                session.ipAddress(),
                Instant.ofEpochMilli(session.start()),
                Instant.ofEpochMilli(session.lastAccess()),
                session.clients() == null ? Map.of() : Map.copyOf(session.clients())
            ))
            .toList();
    }

    public void revokeSession(String sessionId) {
        http.delete()
            .uri("/admin/realms/{realm}/sessions/{sessionId}", realm, sessionId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .toBodilessEntity();
    }

    public void setUserEnabled(UUID accountId, boolean enabled) {
        http.put()
            .uri("/admin/realms/{realm}/users/{userId}", realm, accountId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("enabled", enabled))
            .retrieve()
            .toBodilessEntity();
    }

    public void logoutUser(UUID accountId) {
        http.post()
            .uri("/admin/realms/{realm}/users/{userId}/logout", realm, accountId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .toBodilessEntity();
    }

    public void clearUserLoginFailures(UUID accountId) {
        http.delete()
            .uri("/admin/realms/{realm}/attack-detection/brute-force/users/{userId}", realm, accountId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .toBodilessEntity();
    }

    public BruteForceStatus bruteForceStatus(UUID accountId) {
        var response = http.get()
            .uri("/admin/realms/{realm}/attack-detection/brute-force/users/{userId}", realm, accountId)
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .body(BruteForceRepresentation.class);
        if (response == null) return new BruteForceStatus(false, 0, null, null);
        return new BruteForceStatus(
            response.disabled(), response.numFailures(), response.lastIPFailure(),
            response.lastFailure() > 0 ? Instant.ofEpochMilli(response.lastFailure()) : null
        );
    }

    private UserSummary findExactUserByEmail(String targetRealm, String email) {
        var users = http.get()
            .uri(uri -> uri
                .path("/admin/realms/{realm}/users")
                .queryParam("email", email)
                .queryParam("exact", true)
                .queryParam("max", 2)
                .build(targetRealm))
            .headers(headers -> headers.setBearerAuth(accessToken()))
            .retrieve()
            .body(UserSummary[].class);
        if (users == null || users.length == 0) {
            return null;
        }
        if (users.length > 1) {
            throw new IllegalStateException("Keycloak returned multiple exact users for one email");
        }
        return users[0];
    }

    private static HostIdentity verifyHostIdentity(UserSummary existing, UUID invitationId) {
        var invitation = firstAttribute(existing.attributes(), "vistay_invitation_id");
        if (!invitationId.toString().equals(invitation)) {
            throw new HostSubjectCollisionException();
        }
        return new HostIdentity(existing.id());
    }

    private static String firstAttribute(Map<String, List<String>> attributes, String name) {
        if (attributes == null || attributes.get(name) == null || attributes.get(name).isEmpty()) {
            return null;
        }
        return attributes.get(name).getFirst();
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
    private record UserSummary(
        String id,
        Boolean emailVerified,
        Boolean enabled,
        List<String> requiredActions,
        Map<String, List<String>> attributes
    ) {}
    private record UserSessionRepresentation(
        String id,
        String ipAddress,
        long start,
        long lastAccess,
        Map<String, String> clients
    ) {}
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
    private record BruteForceRepresentation(
        boolean disabled,
        int numFailures,
        String lastIPFailure,
        long lastFailure
    ) {}

    public record ActiveSession(
        String id,
        String ipAddress,
        Instant startedAt,
        Instant lastAccessAt,
        Map<String, String> clients
    ) {}
    public record BruteForceStatus(
        boolean temporarilyLocked,
        int failureCount,
        String lastFailureIp,
        Instant lastFailureAt
    ) {}

    public record HostIdentity(String subject) {}
    public record HostActivationState(
        boolean emailVerified,
        boolean enabled,
        List<String> requiredActions
    ) {}

    public static final class HostSubjectCollisionException extends RuntimeException {
        public HostSubjectCollisionException() {
            super("HOST_SUBJECT_COLLISION");
        }
    }
}
