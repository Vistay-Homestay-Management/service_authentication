package com.vistay.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class IdentityPolicyProjectionMigrationTest {
    @Test
    void storesMonotonicUserOwnedRegistrationPolicyProjection() throws Exception {
        var sql = Files.readString(Path.of(
            "src/main/resources/db/migration/V13__identity_policy_projection.sql"));
        assertThat(sql)
            .contains("identity_policy_projection")
            .contains("policy_version bigint NOT NULL")
            .contains("registration_enabled boolean NOT NULL")
            .contains("AUTO_LINK", "REQUIRE_APPROVAL")
            .contains("source_event_id uuid NOT NULL UNIQUE");
    }
}
