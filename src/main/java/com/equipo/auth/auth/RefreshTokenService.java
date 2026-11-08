package com.equipo.auth.auth;

import com.equipo.auth.common.LogSanitizer;
import com.equipo.auth.config.JwtProperties;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ciclo de vida de los refresh tokens: emisión, rotación con detección de reutilización y revocación.
 *
 * <p>Cada token es de un solo uso. Si un token ya usado se presenta de nuevo, alguien lo copió: se
 * revoca toda la familia (el atacante y la víctima pierden la sesión y la víctima debe iniciar sesión).
 */
@Service
public class RefreshTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository repository;
    private final TokenHasher hasher;
    private final JwtProperties properties;
    private final Clock clock;

    public RefreshTokenService(RefreshTokenRepository repository, TokenHasher hasher, JwtProperties properties,
            Clock clock) {
        this.repository = repository;
        this.hasher = hasher;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Resultado de emitir o rotar un refresh token.
     *
     * @param userId dueño del token
     * @param token  valor en claro para el cliente
     */
    public record Issued(UUID userId, String token) {

        @Override
        public String toString() {
            return "Issued[userId=" + userId + ", token=****]";
        }
    }

    /**
     * Emite un refresh token en una familia nueva (login).
     *
     * @param userId dueño
     * @return token emitido
     */
    @Transactional
    public Issued issueNewFamily(UUID userId) {
        return issue(userId, UUID.randomUUID());
    }

    /**
     * Rota un refresh token: lo invalida y emite otro de la misma familia.
     *
     * <p>{@code noRollbackFor}: la revocación de la familia ante una reutilización debe confirmarse
     * aunque el método termine lanzando la excepción.
     *
     * @param rawToken token presentado por el cliente
     * @return nuevo token
     * @throws InvalidTokenException si no existe, expiró o ya fue usado (en este caso revoca la familia)
     */
    @Transactional(noRollbackFor = InvalidTokenException.class)
    public Issued rotate(String rawToken) {
        Instant now = clock.instant();
        RefreshToken current = repository.findByTokenHash(hasher.hash(rawToken))
                .orElseThrow(InvalidTokenException::new);
        if (current.isRevoked()) {
            int revoked = repository.revokeFamily(current.getFamilyId(), now);
            LOG.warn("SECURITY refresh_token_reuse user={} family={} revoked={}",
                    LogSanitizer.safe(current.getUserId()), LogSanitizer.safe(current.getFamilyId()), revoked);
            throw new InvalidTokenException();
        }
        if (current.isExpired(now)) {
            throw new InvalidTokenException();
        }
        current.revoke(now);
        repository.saveAndFlush(current);
        return issue(current.getUserId(), current.getFamilyId());
    }

    /**
     * Revoca la familia del token si pertenece al usuario (logout).
     *
     * @param rawToken token presentado
     * @param userId   usuario autenticado por el access token
     * @throws InvalidTokenException si el token no existe o es de otro usuario
     */
    @Transactional
    public void revokeFamily(String rawToken, UUID userId) {
        RefreshToken token = repository.findByTokenHash(hasher.hash(rawToken))
                .filter(t -> t.getUserId().equals(userId))
                .orElseThrow(InvalidTokenException::new);
        repository.revokeFamily(token.getFamilyId(), clock.instant());
    }

    /** Segundos de vigencia del refresh token. */
    public long ttlSeconds() {
        return properties.refreshTokenTtl().toSeconds();
    }

    private Issued issue(UUID userId, UUID familyId) {
        Instant now = clock.instant();
        String raw = hasher.newToken();
        repository.save(new RefreshToken(hasher.hash(raw), userId, familyId, now,
                now.plus(properties.refreshTokenTtl())));
        return new Issued(userId, raw);
    }
}
