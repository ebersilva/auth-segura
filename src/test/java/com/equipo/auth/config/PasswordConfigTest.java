package com.equipo.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordConfigTest {

    private final PasswordEncoder encoder = new PasswordConfig().passwordEncoder();

    @Test
    void encode_usaArgon2idConParametrosOwasp() {
        String hash = encoder.encode("Correcta-Caballo-42");
        assertThat(hash).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
    }

    @Test
    void encode_usaSalAleatoria() {
        assertThat(encoder.encode("misma-clave-123")).isNotEqualTo(encoder.encode("misma-clave-123"));
    }

    @Test
    void matches_soloConLaContrasenaCorrecta() {
        String hash = encoder.encode("Correcta-Caballo-42");
        assertThat(encoder.matches("Correcta-Caballo-42", hash)).isTrue();
        assertThat(encoder.matches("correcta-caballo-42", hash)).isFalse();
    }
}
