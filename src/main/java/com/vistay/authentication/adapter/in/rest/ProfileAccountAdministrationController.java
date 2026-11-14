package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AuthorizationClient;
import com.vistay.authentication.application.ProfileAccountAdministrationService;
import com.vistay.authentication.application.ProfileAccountAdministrationService.Command;
import com.vistay.authentication.application.ProfileAccountAdministrationService.ProfileAccountResult;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
@RequestMapping("/api/v1/profile-accounts")
public class ProfileAccountAdministrationController {
    private final ProfileAccountAdministrationService accounts;
    private final AuthorizationClient authorizations;

    public ProfileAccountAdministrationController(
        ProfileAccountAdministrationService accounts,
        AuthorizationClient authorizations
    ) {
        this.accounts = accounts;
        this.authorizations = authorizations;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    ProfileAccountResult create(
        @AuthenticationPrincipal Jwt jwt,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @Valid @RequestBody ProfileAccountCommand request
    ) {
        var actor = actor(jwt);
        authorizations.require(actor,
            ProfileAccountAdministrationService.permission(request.accountType()));
        return accounts.execute(actor, idempotencyKey, new Command(
            request.profileId(), request.accountType(), request.email(), request.displayName(),
            request.mode(), request.temporaryPassword(), request.reason()
        ));
    }

    private static UUID actor(Jwt jwt) {
        try { return UUID.fromString(jwt.getSubject()); }
        catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "INVALID_ADMIN_TOKEN");
        }
    }

    public record ProfileAccountCommand(
        @NotNull UUID profileId,
        @NotBlank String accountType,
        @Email @NotBlank String email,
        @NotBlank @Size(max = 180) String displayName,
        @NotBlank String mode,
        @Size(max = 128) String temporaryPassword,
        @NotBlank @Size(min = 8, max = 500) String reason
    ) {}
}
