package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AccountLifecycleService;
import com.vistay.authentication.application.AccountLifecycleService.AccountSecurityView;
import com.vistay.authentication.application.AccountLifecycleService.LifecycleAction;
import com.vistay.authentication.application.AccountLifecycleService.LifecycleEvent;
import com.vistay.authentication.application.AccountLifecycleService.LifecycleResult;
import com.vistay.authentication.application.AuthorizationClient;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/backoffice/accounts/{accountId}")
public class AccountLifecycleController {
    private final AccountLifecycleService lifecycle;
    private final AuthorizationClient authorizations;

    public AccountLifecycleController(
        AccountLifecycleService lifecycle,
        AuthorizationClient authorizations
    ) {
        this.lifecycle = lifecycle;
        this.authorizations = authorizations;
    }

    @GetMapping
    AccountSecurityView get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID accountId) {
        authorizations.require(subject(jwt), "account:read");
        return lifecycle.get(accountId);
    }

    @GetMapping("/security-events")
    List<LifecycleEvent> events(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID accountId) {
        var actor = subject(jwt);
        authorizations.require(actor, "account:read");
        authorizations.require(actor, "audit:read");
        return lifecycle.events(accountId);
    }

    @PostMapping("/lifecycle")
    LifecycleResult change(
        @AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID accountId,
        @RequestHeader("Idempotency-Key") String idempotencyKey,
        @RequestHeader(name = "X-Correlation-Id", required = false) String correlationId,
        @Valid @RequestBody LifecycleChange request
    ) {
        var actor = subject(jwt);
        authorizations.require(actor, request.action() == LifecycleAction.RECOVER
            ? "account:unlock" : "account:suspend");
        return lifecycle.change(idempotencyKey, actor, accountId, request.action(),
            request.expectedVersion(), request.reason(), correlationId);
    }

    private static UUID subject(Jwt jwt) {
        try { return UUID.fromString(jwt.getSubject()); }
        catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid administrator token");
        }
    }

    public record LifecycleChange(
        @NotNull LifecycleAction action,
        @Min(0) long expectedVersion,
        @NotBlank @Size(min = 8, max = 500) String reason
    ) {}
}
