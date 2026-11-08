package com.equipo.auth.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class UserTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    @Test
    void registerFailedLogin_bloqueaAlMaximoYReiniciaContador() {
        User user = new User("ana", "a@b.com", "Ana", "H", NOW);
        assertThat(user.registerFailedLogin(NOW, 2, Duration.ofMinutes(15))).isFalse();
        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(user.registerFailedLogin(NOW, 2, Duration.ofMinutes(15))).isTrue();
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(user.isLocked(NOW)).isTrue();
    }

    @Test
    void resetFailedLogins_quitaBloqueo() {
        User user = new User("ana", "a@b.com", "Ana", "H", NOW);
        user.registerFailedLogin(NOW, 1, Duration.ofMinutes(15));
        user.resetFailedLogins();
        assertThat(user.isLocked(NOW)).isFalse();
        assertThat(user.getLockedUntil()).isNull();
    }

    @Test
    void nuevoUsuario_tieneRolUserYNoEstaBloqueado() {
        User user = new User("ana", "a@b.com", "Ana", "H", NOW);
        assertThat(user.getRole()).isEqualTo(Role.USER);
        assertThat(user.isLocked(NOW)).isFalse();
        assertThat(user.getId()).isNotNull();
    }
}
