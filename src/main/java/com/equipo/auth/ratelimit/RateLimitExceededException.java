package com.equipo.auth.ratelimit;

/** Se superó el límite de peticiones; se responde 429 con {@code Retry-After}. */
public class RateLimitExceededException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long retryAfterSeconds;

    /**
     * Crea la excepción.
     *
     * @param retryAfterSeconds segundos que el cliente debe esperar
     */
    public RateLimitExceededException(long retryAfterSeconds) {
        super("Demasiadas solicitudes. Intenta de nuevo más tarde");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
