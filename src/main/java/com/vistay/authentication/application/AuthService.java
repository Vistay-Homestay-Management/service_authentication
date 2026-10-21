package com.vistay.authentication.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;

import com.vistay.authentication.domain.AccountType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(15);
    private static final Duration REFRESH_IDLE_LIFETIME = Duration.ofDays(7);
    private static final Duration REFRESH_ABSOLUTE_LIFETIME = Duration.ofDays(30);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcClient jdbc;
    private final PasswordEncoder passwords;
    private final JwtEncoder jwtEncoder;
    private final StringRedisTemplate redis;
    private final String issuer;

    public AuthService(
        JdbcClient jdbc,
        PasswordEncoder passwords,
        JwtEncoder jwtEncoder,
        StringRedisTemplate redis,
        @Value("${vistay.security.issuer}") String issuer
    ) {
        this.jdbc = jdbc;
        this.passwords = passwords;
        this.jwtEncoder = jwtEncoder;
        this.redis = redis;
        this.issuer = issuer;
    }

    @Transactional
    public UUID registerCustomer(String email, String rawPassword) {
        var normalizedEmail = normalizeIdentifier(email);
        validatePassword(rawPassword);
        try {
            return jdbc.sql("""
                INSERT INTO customer_accounts(email, password_hash, status, email_verified_at)
                VALUES (:email, :passwordHash, 'ACTIVE', now())
                RETURNING id
                """)
                .param("email", normalizedEmail)
                .param("passwordHash", passwords.encode(rawPassword))
                .query(UUID.class)
                .single();
        } catch (DataIntegrityViolationException duplicate) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Customer account already exists");
        }
    }

    @Transactional
    public TokenPair login(AccountType type, String identifier, String rawPassword, String clientId) {
        var account = findAccount(type, normalizeIdentifier(identifier));
        if (account == null || !passwords.matches(rawPassword, account.passwordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        if (!"ACTIVE".equals(account.status())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is not active");
        }

        var now = Instant.now();
        var sessionId = UUID.randomUUID();
        var refreshToken = newRefreshToken(sessionId);
        jdbc.sql("""
            INSERT INTO auth_sessions(
                id, account_type, account_id, client_id, refresh_token_hash,
                token_family_id, idle_expires_at, absolute_expires_at
            ) VALUES (
                :id, :accountType, :accountId, :clientId, :refreshHash,
                :familyId, :idleExpiresAt, :absoluteExpiresAt
            )
            """)
            .param("id", sessionId)
            .param("accountType", type.name())
            .param("accountId", account.id())
            .param("clientId", clientId)
            .param("refreshHash", sha256(refreshToken))
            .param("familyId", UUID.randomUUID())
            .param("idleExpiresAt", atUtc(now.plus(REFRESH_IDLE_LIFETIME)))
            .param("absoluteExpiresAt", atUtc(now.plus(REFRESH_ABSOLUTE_LIFETIME)))
            .update();
        jdbc.sql("UPDATE " + type.tableName() + " SET last_login_at = now(), failed_login_attempts = 0 WHERE id = :id")
            .param("id", account.id())
            .update();
        return issuePair(account, type, sessionId, refreshToken, now);
    }

    @Transactional
    public TokenPair refresh(String presentedToken, String clientId) {
        var sessionId = parseSessionId(presentedToken);
        var session = jdbc.sql("""
            SELECT id, account_type, account_id, client_id, refresh_token_hash,
                   idle_expires_at, absolute_expires_at, revoked_at
            FROM auth_sessions WHERE id = :id FOR UPDATE
            """)
            .param("id", sessionId)
            .query(SessionRow.class)
            .optional()
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        if (!MessageDigest.isEqual(
            session.refreshTokenHash().getBytes(StandardCharsets.US_ASCII),
            sha256(presentedToken).getBytes(StandardCharsets.US_ASCII)
        )) {
            revokeSession(session.id(), "REFRESH_TOKEN_REPLAY");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token replay detected");
        }

        var now = Instant.now();
        if (session.revokedAt() != null || !session.clientId().equals(clientId)
            || session.idleExpiresAt().toInstant().isBefore(now)
            || session.absoluteExpiresAt().toInstant().isBefore(now)) {
            revokeSession(session.id(), "REFRESH_TOKEN_EXPIRED_OR_INVALID");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh session expired");
        }

        var type = AccountType.valueOf(session.accountType());
        var account = findAccountById(type, session.accountId());
        if (account == null || !"ACTIVE".equals(account.status())) {
            revokeSession(session.id(), "ACCOUNT_INACTIVE");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is not active");
        }

        var rotated = newRefreshToken(session.id());
        var idleExpiry = atUtc(min(now.plus(REFRESH_IDLE_LIFETIME), session.absoluteExpiresAt().toInstant()));
        jdbc.sql("""
            UPDATE auth_sessions
            SET refresh_token_hash = :hash, last_seen_at = now(), idle_expires_at = :idleExpiry
            WHERE id = :id
            """)
            .param("hash", sha256(rotated))
            .param("idleExpiry", idleExpiry)
            .param("id", session.id())
            .update();
        return issuePair(account, type, session.id(), rotated, now);
    }

    @Transactional
    public void logout(UUID sessionId, String accessTokenId, Instant accessExpiry) {
        revokeSession(sessionId, "LOGOUT");
        var ttl = Duration.between(Instant.now(), accessExpiry);
        if (!ttl.isNegative() && !ttl.isZero()) {
            redis.opsForValue().set("auth:revoked:jti:" + accessTokenId, "1", ttl);
        }
    }

    private AccountRow findAccount(AccountType type, String identifier) {
        return jdbc.sql("""
            SELECT id, password_hash, status, security_version
            FROM %s
            WHERE lower(email::text) = :identifier OR normalized_phone = :identifier
            """.formatted(type.tableName()))
            .param("identifier", identifier)
            .query(AccountRow.class)
            .optional()
            .orElse(null);
    }

    private AccountRow findAccountById(AccountType type, UUID id) {
        return jdbc.sql("""
            SELECT id, password_hash, status, security_version
            FROM %s WHERE id = :id
            """.formatted(type.tableName()))
            .param("id", id)
            .query(AccountRow.class)
            .optional()
            .orElse(null);
    }

    private TokenPair issuePair(AccountRow account, AccountType type, UUID sessionId, String refreshToken, Instant now) {
        var claims = JwtClaimsSet.builder()
            .issuer(issuer).issuedAt(now).expiresAt(now.plus(ACCESS_LIFETIME))
            .subject(account.id().toString()).id(UUID.randomUUID().toString())
            .claim("account_type", type.name())
            .claim("session_id", sessionId.toString())
            .claim("security_version", account.securityVersion())
            .build();
        var header = JwsHeader.with(MacAlgorithm.HS256).type("JWT").build();
        var access = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenPair(access, refreshToken, ACCESS_LIFETIME.toSeconds(), "Bearer");
    }

    private void revokeSession(UUID sessionId, String reason) {
        jdbc.sql("""
            UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()),
                revocation_reason = COALESCE(revocation_reason, :reason)
            WHERE id = :id
            """)
            .param("reason", reason).param("id", sessionId).update();
        redis.opsForValue().set("auth:revoked:session:" + sessionId, "1", REFRESH_ABSOLUTE_LIFETIME);
    }

    private static UUID parseSessionId(String refreshToken) {
        try {
            return UUID.fromString(refreshToken.substring(0, refreshToken.indexOf('.')));
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }
    }

    private static String newRefreshToken(UUID sessionId) {
        var secret = new byte[48];
        RANDOM.nextBytes(secret);
        return sessionId + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }

    private static String normalizeIdentifier(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static void validatePassword(String password) {
        if (password == null || password.length() < 12 || password.length() > 128) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain 12 to 128 characters");
        }
    }

    private static String sha256(String value) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static OffsetDateTime atUtc(Instant value) {
        return value.atOffset(ZoneOffset.UTC);
    }

    private static Instant min(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }

    private record AccountRow(UUID id, String passwordHash, String status, long securityVersion) {}
    private record SessionRow(UUID id, String accountType, UUID accountId, String clientId,
        String refreshTokenHash, OffsetDateTime idleExpiresAt, OffsetDateTime absoluteExpiresAt,
        OffsetDateTime revokedAt) {}
    public record TokenPair(String accessToken, String refreshToken, long expiresInSeconds, String tokenType) {}
}
