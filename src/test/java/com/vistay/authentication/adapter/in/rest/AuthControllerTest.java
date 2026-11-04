package com.vistay.authentication.adapter.in.rest;

import com.vistay.authentication.application.AuthService;
import com.vistay.authentication.application.AuthorizationClient;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthControllerTest {
    private final AuthService auth = mock(AuthService.class);
    private final AuthorizationClient authorizations = mock(AuthorizationClient.class);
    private final AuthController controller = new AuthController(
        auth,
        authorizations,
        "test-bootstrap-token-with-at-least-32-characters"
    );

    @Test
    void authorizedAdministratorCanProvisionAccount() {
        var actorId = UUID.randomUUID();
        var jwt = mock(Jwt.class);
        var request = request();
        var expected = new AuthService.ProvisionedAccount(
            UUID.randomUUID(), UUID.randomUUID().toString(), request.email(),
            "ADMIN", "ACTIVE", 0, OffsetDateTime.now()
        );
        when(jwt.getSubject()).thenReturn(actorId.toString());
        when(auth.provisionBackoffice(
            "request-1", actorId, request.email(), request.fullName(),
            request.temporaryPassword(), request.reason(), "correlation-id"
        )).thenReturn(expected);

        var actual = controller.provision(jwt, "request-1", "correlation-id", request);

        assertThat(actual).isEqualTo(expected);
        verify(authorizations).require(actorId, "account:provision");
    }

    @Test
    void permissionDenialStopsProvisioningBeforeKeycloakIsCalled() {
        var actorId = UUID.randomUUID();
        var jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn(actorId.toString());
        doThrow(new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing permission"))
            .when(authorizations).require(actorId, "account:provision");

        assertThatThrownBy(() -> controller.provision(
            jwt, "request-1", null, request()
        )).isInstanceOfSatisfying(ResponseStatusException.class,
            error -> assertThat(error.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
        verify(auth, never()).provisionBackoffice(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any()
        );
    }

    @Test
    void invalidAdministratorSubjectIsUnauthorized() {
        var jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn("not-a-uuid");

        assertThatThrownBy(() -> controller.provision(
            jwt, "request-1", null, request()
        )).isInstanceOfSatisfying(ResponseStatusException.class,
            error -> assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    private static AuthController.ProvisionBackofficeAccount request() {
        return new AuthController.ProvisionBackofficeAccount(
            "operator@vistay.vn",
            "ViStay Operator",
            "temporary-pass-123",
            "Required for operations shift"
        );
    }
}
