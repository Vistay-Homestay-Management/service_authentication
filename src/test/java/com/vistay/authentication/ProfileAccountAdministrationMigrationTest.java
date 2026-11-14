package com.vistay.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ProfileAccountAdministrationMigrationTest {
    @Test
    void keepsProfileTargetAuditedWithoutClaimingTheProfile() throws Exception {
        var sql = Files.readString(Path.of(
            "src/main/resources/db/migration/V14__profile_account_administration.sql"));
        assertThat(sql)
            .contains("target_profile_id uuid NOT NULL")
            .contains("mode IN ('DIRECT', 'INVITATION')")
            .contains("idempotency_key varchar(160) NOT NULL UNIQUE")
            .contains("UNIQUE (account_type, target_profile_id)")
            .contains("actor_account_id uuid NOT NULL")
            .doesNotContain("profile_account_links")
            .doesNotContain("UPDATE customers")
            .doesNotContain("UPDATE hosts")
            .doesNotContain("UPDATE admin_users");
    }
}
