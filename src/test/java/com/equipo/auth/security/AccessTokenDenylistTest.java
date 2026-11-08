package com.equipo.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.support.MutableClock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AccessTokenDenylistTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-07T12:00:00Z"));
    private final AccessTokenDenylist denylist = new AccessTokenDenylist(clock);

    @Test
    void revoke_marcaElJtiComoRevocado() {
        denylist.revoke("a", clock.instant().plusSeconds(60));
        assertThat(denylist.isRevoked("a")).isTrue();
        assertThat(denylist.isRevoked("b")).isFalse();
        assertThat(denylist.isRevoked(null)).isFalse();
    }

    @Test
    void purgeExpired_eliminaEntradasDeTokensYaExpirados() {
        // Arrange
        denylist.revoke("corto", clock.instant().plusSeconds(60));
        denylist.revoke("largo", clock.instant().plusSeconds(900));
        clock.advance(Duration.ofSeconds(60));

        // Act: la purga también se ejecuta en cada revoke
        denylist.purgeExpired();

        // Assert: memoria acotada a los tokens que aún podrían usarse
        assertThat(denylist.size()).isEqualTo(1);
        assertThat(denylist.isRevoked("largo")).isTrue();
    }

    @Test
    void revoke_purgaLasEntradasExpiradasAutomaticamente() {
        // Arrange
        denylist.revoke("viejo", clock.instant().plusSeconds(60));
        clock.advance(Duration.ofSeconds(61));

        // Act: un logout posterior limpia lo expirado sin tarea programada
        denylist.revoke("nuevo", clock.instant().plusSeconds(900));

        // Assert
        assertThat(denylist.size()).isEqualTo(1);
        assertThat(denylist.isRevoked("viejo")).isFalse();
    }
}
