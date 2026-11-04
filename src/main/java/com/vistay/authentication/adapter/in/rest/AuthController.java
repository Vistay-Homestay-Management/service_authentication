package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AuthService;
import com.vistay.authentication.application.AuthService.ProvisionedAccount;
import com.vistay.authentication.application.AuthorizationClient;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

@RestController
@RequestMapping("/api/v1/backoffice/accounts")
public class AuthController {
    private final AuthService auth;
    private final AuthorizationClient authorizations;
    private final byte[] bootstrapToken;

    public AuthController(
        AuthService auth,
        AuthorizationClient authorizations,
        @Value("${vistay.bootstrap.token}") String bootstrapToken
    ) {
        if (bootstrapToken == null || bootstrapToken.length() < 32) {
            throw new IllegalStateException("VISTAY_BOOTSTRAP_TOKEN must contain at least 32 characters");
        }
        this.auth = auth;
        this.authorizations = authorizations;
        this.bootstrapToken = bootstrapToken.getBytes(StandardCharsets.UTF_8);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    ProvisionedAccount provision(
        @AuthenticationPrincipal Jwt jwt,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody ProvisionBackofficeAccount request
    ) {
        UUID accountId;
        try {
            accountId = UUID.fromString(jwt.getSubject());
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
        authorizations.require(accountId, "account:provision");
        return auth.provisionBackoffice(
            idempotencyKey,
            accountId,
            request.email(),
            request.fullName(),
            request.temporaryPassword(),
            request.reason(),
            correlationId
        );
    }

    @PostMapping("/bootstrap")
    @ResponseStatus(HttpStatus.CREATED)
    ProvisionedAccount bootstrap(
        @RequestHeader("X-ViStay-Bootstrap-Token") String presentedBootstrapToken,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody ProvisionBackofficeAccount request
    ) {
        if (!MessageDigest.isEqual(
            bootstrapToken,
            presentedBootstrapToken.getBytes(StandardCharsets.UTF_8)
        )) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid bootstrap credential");
        }
        return auth.bootstrapBackoffice(
            idempotencyKey,
            request.email(),
            request.fullName(),
            request.temporaryPassword(),
            request.reason(),
            correlationId
        );
    }

    public record ProvisionBackofficeAccount(
        @Email @NotBlank String email,
        @NotBlank @Size(max = 180) String fullName,
        @NotBlank @Size(min = 12, max = 128) String temporaryPassword,
        @NotBlank @Size(min = 8, max = 500) String reason
    ) {}
}
