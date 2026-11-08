package com.equipo.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.equipo.auth.support.MutableClock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class RateLimiterTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-07T12:00:00Z"));

    @Test
    void tryAcquire_dentroDeCapacidad_permite() {
        // Arrange
        RateLimiter limiter = new RateLimiter(3, Duration.ofMinutes(1), clock);

        // Act + Assert
        for (int i = 0; i < 3; i++) {
            assertThat(limiter.tryAcquire("k").allowed()).isTrue();
        }
    }

    @Test
    void tryAcquire_excedeCapacidad_rechazaConRetryAfter() {
        // Arrange: 3 fichas por minuto = una ficha cada 20 s
        RateLimiter limiter = new RateLimiter(3, Duration.ofMinutes(1), clock);
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire("k");
        }

        // Act
        RateLimiter.Decision decision = limiter.tryAcquire("k");

        // Assert
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.retryAfterSeconds()).isEqualTo(20);
    }

    @Test
    void tryAcquire_retryAfterSeRedondeaHaciaArribaYNuncaEsCero() {
        // Arrange: 1 ficha cada 1,5 s; tras 1 s falta medio segundo
        RateLimiter limiter = new RateLimiter(2, Duration.ofSeconds(3), clock);
        limiter.tryAcquire("k");
        limiter.tryAcquire("k");
        clock.advance(Duration.ofMillis(1000));

        // Act + Assert
        assertThat(limiter.tryAcquire("k").retryAfterSeconds()).isEqualTo(1);
    }

    @Test
    void tryAcquire_trasRecarga_vuelveAPermitir() {
        // Arrange
        RateLimiter limiter = new RateLimiter(3, Duration.ofMinutes(1), clock);
        for (int i = 0; i < 4; i++) {
            limiter.tryAcquire("k");
        }

        // Act: a los 19 s todavía no hay ficha; a los 20 s sí
        clock.advance(Duration.ofSeconds(19));
        boolean at19 = limiter.tryAcquire("k").allowed();
        clock.advance(Duration.ofSeconds(1));
        boolean at20 = limiter.tryAcquire("k").allowed();

        // Assert
        assertThat(at19).isFalse();
        assertThat(at20).isTrue();
    }

    @Test
    void tryAcquire_recargaNoSuperaCapacidad() {
        // Arrange
        RateLimiter limiter = new RateLimiter(2, Duration.ofMinutes(1), clock);
        clock.advance(Duration.ofHours(1));

        // Act + Assert: tras una hora inactiva sigue habiendo solo 2 fichas
        assertThat(limiter.tryAcquire("k").allowed()).isTrue();
        assertThat(limiter.tryAcquire("k").allowed()).isTrue();
        assertThat(limiter.tryAcquire("k").allowed()).isFalse();
    }

    @Test
    void tryAcquire_clavesIndependientes() {
        RateLimiter limiter = new RateLimiter(1, Duration.ofMinutes(1), clock);
        assertThat(limiter.tryAcquire("a").allowed()).isTrue();
        assertThat(limiter.tryAcquire("a").allowed()).isFalse();
        assertThat(limiter.tryAcquire("b").allowed()).isTrue();
    }

    @Test
    void tryAcquire_concurrente_nuncaExcedeCapacidad() throws Exception {
        // Arrange
        RateLimiter limiter = new RateLimiter(50, Duration.ofMinutes(1), clock);
        AtomicInteger allowed = new AtomicInteger();

        // Act: 500 intentos desde 16 hilos
        try (ExecutorService pool = Executors.newFixedThreadPool(16)) {
            for (int i = 0; i < 500; i++) {
                pool.submit(() -> {
                    if (limiter.tryAcquire("k").allowed()) {
                        allowed.incrementAndGet();
                    }
                });
            }
        }

        // Assert
        assertThat(allowed.get()).isEqualTo(50);
    }

    @Test
    void evictFullBuckets_eliminaSoloLasRecargadas() {
        // Arrange
        RateLimiter limiter = new RateLimiter(2, Duration.ofMinutes(1), clock);
        limiter.tryAcquire("inactiva");
        clock.advance(Duration.ofMinutes(1));
        limiter.tryAcquire("activa");

        // Act
        limiter.evictFullBuckets();

        // Assert
        assertThat(limiter.trackedKeys()).isEqualTo(1);
    }

    @Test
    void tryAcquire_alSuperarUmbral_desalojaCubetasInactivas() {
        // Arrange: llena el mapa hasta el umbral con claves de un solo uso
        RateLimiter limiter = new RateLimiter(5, Duration.ofSeconds(1), clock);
        for (int i = 0; i < RateLimiter.EVICTION_THRESHOLD; i++) {
            limiter.tryAcquire("ip-" + i);
        }
        clock.advance(Duration.ofSeconds(1));

        // Act: la siguiente petición dispara el desalojo
        limiter.tryAcquire("nueva");

        // Assert: memoria acotada ante un atacante que rota claves
        assertThat(limiter.trackedKeys()).isEqualTo(1);
    }

    @Test
    void constructor_parametrosInvalidos_lanza() {
        assertThatThrownBy(() -> new RateLimiter(0, Duration.ofMinutes(1), clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RateLimiter(1, Duration.ZERO, clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RateLimiter(1, Duration.ofSeconds(-1), clock))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
