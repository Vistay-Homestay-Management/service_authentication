package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AuthorizationClient;
import com.vistay.authentication.application.HostInvitationService;
import com.vistay.authentication.application.HostInvitationService.HostAccount;
import com.vistay.authentication.application.HostInvitationService.HostInvitation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping({"/api/v1/host-accounts", "/v1/host/invitations"})
public class HostInvitationController {
    private final HostInvitationService invitations;
    private final AuthorizationClient authorizations;

    public HostInvitationController(
        HostInvitationService invitations,
        AuthorizationClient authorizations
    ) {
        this.invitations = invitations;
        this.authorizations = authorizations;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    HostInvitation invite(
        @AuthenticationPrincipal Jwt jwt,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody HostInvitationRequest request
    ) {
        var actor = subject(jwt);
        authorizations.requireAnyScope(actor, "host-account:invite", "ALL", "SITE", "BRANCH");
        return invitations.invite(
            idempotencyKey,
            actor,
            request.email(),
            request.displayName(),
            request.phone(),
            request.reason(),
            request.accountType(),
            request.propertyId(),
            request.branchId(),
            correlationId
        );
    }

    @PostMapping("/{invitationId}/resend")
    HostInvitation resend(
        @AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID invitationId,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody(required = false) ResendInvitation request
    ) {
        var actor = subject(jwt);
        authorizations.requireAnyScope(
            actor, "host-account:invitation:resend", "ALL", "SITE", "BRANCH"
        );
        var reason = request == null ? "Operator requested invitation resend" : request.reason();
        return invitations.resend(idempotencyKey, actor, invitationId, reason, correlationId);
    }

    @PostMapping("/{invitationId}/activate")
    HostAccount activate(
        @AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID invitationId,
        @Valid @RequestBody ActivationObservation request,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId
    ) {
        return invitations.activate(
            invitationId, hostSubject(jwt), request.expectedVersion(), correlationId
        );
    }

    private static UUID subject(Jwt jwt) {
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
    }

    private static String hostSubject(Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Host token");
        }
        return jwt.getSubject();
    }

    public record HostInvitationRequest(
        @Email @NotBlank String email,
        @NotBlank @Size(max = 180) String displayName,
        @Size(max = 40) String phone,
        @NotBlank @Size(min = 8, max = 500) String reason,
        @Size(max = 16) String accountType,
        @NotNull UUID propertyId,
        @NotNull UUID branchId
    ) {
        public HostInvitationRequest(
            String email,
            String displayName,
            String phone,
            String reason
        ) {
            this(email, displayName, phone, reason, "HOST", null, null);
        }
    }

    public record ResendInvitation(
        @NotBlank @Size(min = 8, max = 500) String reason
    ) {}

    public record ActivationObservation(@NotNull @Min(1) Long expectedVersion) {}
}
