package com.equipo.auth.ratelimit;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiter de tipo token bucket, en memoria y thread-safe, con una cubeta por clave.
 *
 * <p>Cada cubeta tiene {@code capacity} fichas y se recarga de forma continua: {@code capacity}
 * fichas cada {@code refillPeriod}. Cada petición consume una ficha. Con una sola instancia de la
 * aplicación es suficiente; con varias, el estado debe moverse a un almacén compartido (Redis).
 */
public final class RateLimiter {

    /** Número de claves a partir del cual se desalojan las cubetas llenas (inactivas). */
    static final int EVICTION_THRESHOLD = 10_000;

    private final int capacity;
    private final double nanosPerToken;
    private final Clock clock;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    /**
     * Crea el limitador.
     *
     * @param capacity     fichas por periodo (ráfaga máxima)
     * @param refillPeriod periodo de recarga completa
     * @param clock        reloj (controlable en tests)
     */
    public RateLimiter(int capacity, Duration refillPeriod, Clock clock) {
        if (capacity < 1 || refillPeriod.isZero() || refillPeriod.isNegative()) {
            throw new IllegalArgumentException("capacity y refillPeriod deben ser positivos");
        }
        this.capacity = capacity;
        this.nanosPerToken = (double) refillPeriod.toNanos() / capacity;
        this.clock = clock;
    }

    /**
     * Resultado de un intento.
     *
     * @param allowed           si la petición puede continuar
     * @param retryAfterSeconds segundos hasta la siguiente ficha (0 si se permitió)
     */
    public record Decision(boolean allowed, long retryAfterSeconds) {
    }

    /**
     * Intenta consumir una ficha de la cubeta de la clave.
     *
     * @param key identificador (IP, usuario…)
     * @return decisión
     */
    public Decision tryAcquire(String key) {
        if (buckets.size() >= EVICTION_THRESHOLD) {
            evictFullBuckets();
        }
        Instant now = clock.instant();
        return buckets.computeIfAbsent(key, k -> new Bucket(capacity, now)).tryConsume(now);
    }

    /** Elimina las cubetas que ya se recargaron por completo: equivalen a una cubeta nueva. */
    void evictFullBuckets() {
        Instant now = clock.instant();
        buckets.values().removeIf(b -> b.isFull(now));
    }

    /** Número de claves con cubeta (para pruebas y métricas). */
    int trackedKeys() {
        return buckets.size();
    }

    private final class Bucket {
        private double tokens;
        private Instant lastRefill;

        Bucket(double tokens, Instant now) {
            this.tokens = tokens;
            this.lastRefill = now;
        }

        synchronized Decision tryConsume(Instant now) {
            refill(now);
            if (tokens >= 1) {
                tokens -= 1;
                return new Decision(true, 0);
            }
            long waitNanos = (long) Math.ceil((1 - tokens) * nanosPerToken);
            long seconds = Math.max(1, (long) Math.ceil(waitNanos / 1_000_000_000.0));
            return new Decision(false, seconds);
        }

        synchronized boolean isFull(Instant now) {
            refill(now);
            return tokens >= capacity;
        }

        private void refill(Instant now) {
            long elapsed = Duration.between(lastRefill, now).toNanos();
            if (elapsed > 0) {
                tokens = Math.min(capacity, tokens + elapsed / nanosPerToken);
                lastRefill = now;
            }
        }
    }
}
