package com.equipo.auth.security;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Access tokens revocados por logout antes de su expiración, identificados por {@code jti}.
 *
 * <p>Cada entrada se conserva solo hasta el {@code exp} del token (máx. 15 minutos), así que la
 * memoria está acotada. Con varias instancias se movería a Redis con TTL.
 */
@Component
public class AccessTokenDenylist {

    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();
    private final Clock clock;

    public AccessTokenDenylist(Clock clock) {
        this.clock = clock;
    }

    /**
     * Revoca un token hasta su expiración.
     *
     * @param jti       identificador del token
     * @param expiresAt expiración del token
     */
    public void revoke(String jti, Instant expiresAt) {
        purgeExpired();
        revoked.put(jti, expiresAt);
    }

    /** Indica si el {@code jti} está revocado. */
    public boolean isRevoked(String jti) {
        return jti != null && revoked.containsKey(jti);
    }

    /** Elimina las entradas cuyo token ya expiró por sí mismo. */
    void purgeExpired() {
        Instant now = clock.instant();
        revoked.values().removeIf(exp -> !now.isBefore(exp));
    }

    /** Número de entradas vigentes (para pruebas). */
    int size() {
        return revoked.size();
    }
}
