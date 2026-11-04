package com.vistay.authentication.application;

import com.vistay.contracts.common.v1.AccountRef;
import com.vistay.contracts.common.v1.AccountType;
import com.vistay.contracts.common.v1.DataScopeType;
import com.vistay.contracts.user.v1.GetAuthorizationSnapshotRequest;
import com.vistay.contracts.user.v1.UserAuthorizationServiceGrpc;
import io.grpc.StatusRuntimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Component
public class AuthorizationClient {
    private final UserAuthorizationServiceGrpc.UserAuthorizationServiceBlockingStub stub;
    private final Duration deadline;
    private final Duration cacheTtl;
    private final ObjectMapper json;
    private final Map<UUID, CachedSnapshot> cache = new ConcurrentHashMap<>();
    private final Map<UUID, Long> minimumVersions = new ConcurrentHashMap<>();

    public AuthorizationClient(
        GrpcChannelFactory channels,
        ObjectMapper json,
        @Value("${vistay.authorization.grpc-deadline:2s}") Duration deadline,
        @Value("${vistay.authorization.local-cache-ttl:30s}") Duration cacheTtl
    ) {
        this.stub = UserAuthorizationServiceGrpc.newBlockingStub(channels.createChannel("user"));
        this.json = json;
        this.deadline = deadline;
        this.cacheTtl = cacheTtl;
    }

    public Snapshot require(UUID accountId, String permission) {
        var snapshot = requireActive(accountId);
        var scopes = snapshot.grants().get(permission);
        if (scopes == null || !scopes.contains("ALL")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing permission " + permission + "@ALL");
        }
        return snapshot;
    }

    public Snapshot requireActive(UUID accountId) {
        var snapshot = get(accountId);
        if (!snapshot.active()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrator profile is inactive");
        }
        return snapshot;
    }

    public Snapshot get(UUID accountId) {
        var now = Instant.now();
        var minimumVersion = minimumVersions.getOrDefault(accountId, 0L);
        var cached = cache.get(accountId);
        if (cached != null && cached.expiresAt().isAfter(now)
            && cached.snapshot().authorizationVersion() >= minimumVersion) {
            return cached.snapshot();
        }
        try {
            var response = stub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS)
                .getAuthorizationSnapshot(GetAuthorizationSnapshotRequest.newBuilder()
                    .setAccount(AccountRef.newBuilder().setAccountId(accountId.toString())
                        .setAccountType(AccountType.ACCOUNT_TYPE_ADMIN).build())
                    .setMinimumAuthorizationVersion(minimumVersion)
                    .build());
            Map<String, Set<String>> grants = new ConcurrentHashMap<>();
            response.getGrantsList().forEach(grant -> grants.put(grant.getPermissionCode(),
                grant.getScopesList().stream()
                    .filter(scope -> scope != DataScopeType.DATA_SCOPE_TYPE_UNSPECIFIED)
                    .map(scope -> scope.name().substring("DATA_SCOPE_TYPE_".length()))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet())));
            var snapshot = new Snapshot(response.getActive(), response.getProfileId(),
                response.getAuthorizationVersion(), Map.copyOf(grants));
            cache.put(accountId, new CachedSnapshot(snapshot, now.plus(cacheTtl)));
            return snapshot;
        } catch (StatusRuntimeException unavailable) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Authorization service is unavailable", unavailable);
        }
    }

    @KafkaListener(
        topics = "${vistay.topics.authorization-changed:user.authorization-changed.v1}",
        groupId = "${spring.application.name}-authorization-cache"
    )
    public void authorizationChanged(String rawEnvelope) {
        JsonNode envelope = json.readTree(rawEnvelope);
        var data = envelope.get("data");
        if (data == null || !"ADMIN".equals(data.get("accountType").asString())) {
            return;
        }
        var accountId = UUID.fromString(data.get("accountId").asString());
        var version = data.get("authorizationVersion").asLong();
        minimumVersions.merge(accountId, version, Math::max);
        cache.remove(accountId);
    }

    private record CachedSnapshot(Snapshot snapshot, Instant expiresAt) {}
    public record Snapshot(boolean active, String profileId, long authorizationVersion,
        Map<String, Set<String>> grants) {}
}
