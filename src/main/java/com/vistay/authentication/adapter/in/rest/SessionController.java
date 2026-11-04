package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.adapter.out.keycloak.KeycloakAdminClient.ActiveSession;
import com.vistay.authentication.application.AuthorizationClient;
import com.vistay.authentication.application.SessionService;
import com.vistay.authentication.application.SessionService.RevocationResult;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/backoffice/accounts/{accountId}/sessions")
public class SessionController {
    private final SessionService sessions;
    private final AuthorizationClient authorizations;

    public SessionController(SessionService sessions, AuthorizationClient authorizations) {
        this.sessions = sessions;
        this.authorizations = authorizations;
    }

    @GetMapping
    List<SessionView> list(
        @AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID accountId
    ) {
        var actor = subject(jwt);
        authorize(actor, accountId, "account:read");
        var currentSessionId = jwt.getClaimAsString("sid");
        return sessions.list(accountId).stream()
            .map(session -> view(session, currentSessionId))
            .toList();
    }

    @DeleteMapping("/{sessionId}")
    RevocationResult revoke(
        @AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID accountId,
        @PathVariable String sessionId,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody RevokeSession request
    ) {
        var actor = subject(jwt);
        authorize(actor, accountId, "account:revoke_session");
        return sessions.revoke(
            idempotencyKey, actor, accountId, sessionId, request.reason(), correlationId
        );
    }

    private void authorize(UUID actor, UUID target, String permission) {
        if (actor.equals(target)) {
            authorizations.requireActive(actor);
        } else {
            authorizations.require(actor, permission);
        }
    }

    private static UUID subject(Jwt jwt) {
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
    }

    private static SessionView view(ActiveSession session, String currentSessionId) {
        return new SessionView(
            session.id(),
            session.ipAddress(),
            session.startedAt(),
            session.lastAccessAt(),
            session.clients(),
            session.id().equals(currentSessionId)
        );
    }

    public record RevokeSession(@NotBlank @Size(min = 8, max = 500) String reason) {}

    public record SessionView(
        String id,
        String ipAddress,
        Instant startedAt,
        Instant lastAccessAt,
        Map<String, String> clients,
        boolean current
    ) {}
}
