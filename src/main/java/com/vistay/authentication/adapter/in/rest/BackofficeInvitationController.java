package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AuthorizationClient;
import com.vistay.authentication.application.BackofficeInvitationService;
import com.vistay.authentication.application.BackofficeInvitationService.InvitedAccount;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/backoffice/invitations")
public class BackofficeInvitationController {
    private final BackofficeInvitationService invitations;
    private final AuthorizationClient authorizations;

    public BackofficeInvitationController(
        BackofficeInvitationService invitations,
        AuthorizationClient authorizations
    ) {
        this.invitations = invitations;
        this.authorizations = authorizations;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    InvitedAccount invite(
        @AuthenticationPrincipal Jwt jwt,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody InviteBackofficeAccount request
    ) {
        var accountId = authenticatedAccount(jwt);
        authorizations.require(accountId, "account:provision");
        return invitations.invite(
            idempotencyKey,
            accountId,
            request.email(),
            request.fullName(),
            request.reason(),
            correlationId
        );
    }

    private static UUID authenticatedAccount(Jwt jwt) {
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
    }

    public record InviteBackofficeAccount(
        @Email @NotBlank String email,
        @NotBlank @Size(max = 180) String fullName,
        @NotBlank @Size(min = 8, max = 500) String reason
    ) {}
}
