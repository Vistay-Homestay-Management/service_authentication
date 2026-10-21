package com.vistay.authentication.adapter.in.rest;

import java.time.Instant;
import java.util.UUID;
import com.vistay.authentication.application.AuthService;
import com.vistay.authentication.application.AuthService.TokenPair;
import com.vistay.authentication.domain.AccountType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @PostMapping("/register/customer")
    @ResponseStatus(HttpStatus.CREATED)
    RegistrationResponse register(@Valid @RequestBody CustomerRegistration request) {
        return new RegistrationResponse(auth.registerCustomer(request.email(), request.password()));
    }

    @PostMapping("/login")
    TokenPair login(@Valid @RequestBody LoginRequest request) {
        return auth.login(request.accountType(), request.identifier(), request.password(), request.clientId());
    }

    @PostMapping("/refresh")
    TokenPair refresh(@Valid @RequestBody RefreshRequest request) {
        return auth.refresh(request.refreshToken(), request.clientId());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void logout(@AuthenticationPrincipal Jwt jwt) {
        auth.logout(UUID.fromString(jwt.getClaimAsString("session_id")), jwt.getId(),
            jwt.getExpiresAt() == null ? Instant.now() : jwt.getExpiresAt());
    }

    public record CustomerRegistration(
        @Email @NotBlank String email,
        @NotBlank @Size(min = 12, max = 128) String password
    ) {}
    public record RegistrationResponse(UUID accountId) {}
    public record LoginRequest(
        @NotNull AccountType accountType,
        @NotBlank String identifier,
        @NotBlank String password,
        @NotBlank @Size(max = 100) String clientId
    ) {}
    public record RefreshRequest(
        @NotBlank String refreshToken,
        @NotBlank @Size(max = 100) String clientId
    ) {}
}
