package com.equipo.auth.auth;

import com.equipo.auth.common.LogSanitizer;
import com.equipo.auth.config.LockoutProperties;
import com.equipo.auth.ratelimit.RateLimitExceededException;
import com.equipo.auth.ratelimit.RateLimiter;
import com.equipo.auth.ratelimit.RateLimiter.Decision;
import com.equipo.auth.user.User;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Defensas contra fuerza bruta en el login: límite por usuario, bloqueo de cuenta e igualación de
 * tiempos de respuesta.
 */
@Component
public class LoginAttemptGuard {

    private static final Logger LOG = LoggerFactory.getLogger(LoginAttemptGuard.class);

    private final RateLimiter loginRateLimiter;
    private final LockoutProperties lockout;
    private final PasswordEncoder passwordEncoder;
    /** Hash de un valor aleatorio: verificar contra él cuesta lo mismo que verificar una contraseña real. */
    private final String dummyHash;

    /** Crea el guardián y calcula una vez el hash ficticio. */
    public LoginAttemptGuard(@Qualifier("loginRateLimiter") RateLimiter loginRateLimiter, LockoutProperties lockout,
            PasswordEncoder passwordEncoder, TokenHasher hasher) {
        this.loginRateLimiter = loginRateLimiter;
        this.lockout = lockout;
        this.passwordEncoder = passwordEncoder;
        this.dummyHash = passwordEncoder.encode(hasher.newToken());
    }

    /**
     * Consume un intento del usuario.
     *
     * @param username usuario normalizado
     * @throws RateLimitExceededException si superó la capacidad del periodo
     */
    public void checkRateLimit(String username) {
        Decision decision = loginRateLimiter.tryAcquire("login:" + username);
        if (!decision.allowed()) {
            LOG.warn("SECURITY login_rate_limited user={} retry_after={}", LogSanitizer.safe(username),
                    decision.retryAfterSeconds());
            throw new RateLimitExceededException(decision.retryAfterSeconds());
        }
    }

    /** Ejecuta una verificación Argon2 completa sin resultado útil (usuario inexistente o bloqueado). */
    public void spendEquivalentTime(String password) {
        passwordEncoder.matches(password, dummyHash);
    }

    /**
     * Registra un fallo y aplica el bloqueo si corresponde.
     *
     * @param user usuario
     * @param now  instante actual
     * @return {@code true} si la cuenta quedó bloqueada con este intento
     */
    public boolean registerFailure(User user, Instant now) {
        return user.registerFailedLogin(now, lockout.maxFailedAttempts(), lockout.duration());
    }
}
