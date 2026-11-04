package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.ActiveSession;
import com.vistay.authentication.application.AuthorizationClient;
import com.vistay.authentication.application.SessionService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionControllerTest {
    private final SessionService sessions = mock(SessionService.class);
    private final AuthorizationClient authorizations = mock(AuthorizationClient.class);
    private final SessionController controller = new SessionController(sessions, authorizations);

    @Test
    void activeOperatorCanSeeOwnSessionsAndCurrentSessionIsMarked() {
        var actor = UUID.randomUUID();
        var jwt = jwt(actor, "session-1");
        when(sessions.list(actor)).thenReturn(List.of(new ActiveSession(
            "session-1", "127.0.0.1", Instant.now(), Instant.now(), Map.of("web", "Web")
        )));

        var result = controller.list(jwt, actor);

        assertThat(result).singleElement().satisfies(session -> {
            assertThat(session.id()).isEqualTo("session-1");
            assertThat(session.current()).isTrue();
        });
        verify(authorizations).requireActive(actor);
    }

    @Test
    void revokingAnotherAccountSessionRequiresAllScopePermission() {
        var actor = UUID.randomUUID();
        var target = UUID.randomUUID();
        var request = new SessionController.RevokeSession("Compromised operator device");
        var expected = new SessionService.RevocationResult(
            target, "session-2", java.time.OffsetDateTime.now(), false
        );
        when(sessions.revoke("request-1", actor, target, "session-2", request.reason(), "correlation"))
            .thenReturn(expected);

        var result = controller.revoke(
            jwt(actor, "session-1"), target, "session-2", "request-1", "correlation", request
        );

        assertThat(result).isEqualTo(expected);
        verify(authorizations).require(actor, "account:revoke_session");
    }

    private static Jwt jwt(UUID subject, String sessionId) {
        var jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn(subject.toString());
        when(jwt.getClaimAsString("sid")).thenReturn(sessionId);
        return jwt;
    }
}
