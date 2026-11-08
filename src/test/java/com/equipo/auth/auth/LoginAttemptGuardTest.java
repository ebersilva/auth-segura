package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.equipo.auth.config.LockoutProperties;
import com.equipo.auth.ratelimit.RateLimitExceededException;
import com.equipo.auth.ratelimit.RateLimiter;
import com.equipo.auth.support.MutableClock;
import com.equipo.auth.user.User;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class LoginAttemptGuardTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final RateLimiter limiter = new RateLimiter(2, Duration.ofMinutes(1), new MutableClock(NOW));

    private LoginAttemptGuard guard() {
        when(encoder.encode(anyString())).thenReturn("DUMMY");
        return new LoginAttemptGuard(limiter, new LockoutProperties(3, Duration.ofMinutes(15)), encoder,
                new TokenHasher());
    }

    @Test
    void checkRateLimit_excedido_lanzaConRetryAfter() {
        LoginAttemptGuard guard = guard();
        guard.checkRateLimit("ana");
        guard.checkRateLimit("ana");
        assertThatThrownBy(() -> guard.checkRateLimit("ana"))
                .isInstanceOf(RateLimitExceededException.class)
                .extracting("retryAfterSeconds").isEqualTo(30L);
    }

    @Test
    void spendEquivalentTime_verificaContraHashFicticio() {
        guard().spendEquivalentTime("intento");
        verify(encoder).matches("intento", "DUMMY");
    }

    @Test
    void registerFailure_bloqueaAlTercerIntento() {
        LoginAttemptGuard guard = guard();
        User user = new User("ana", "ana@ejemplo.com", "Ana", "H", NOW);
        assertThat(guard.registerFailure(user, NOW)).isFalse();
        assertThat(guard.registerFailure(user, NOW)).isFalse();
        assertThat(guard.registerFailure(user, NOW)).isTrue();
        assertThat(user.isLocked(NOW.plus(Duration.ofMinutes(15)).minusSeconds(1))).isTrue();
        assertThat(user.isLocked(NOW.plus(Duration.ofMinutes(15)))).isFalse();
    }
}
