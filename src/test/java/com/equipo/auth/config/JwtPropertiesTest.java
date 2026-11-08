package com.equipo.auth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class JwtPropertiesTest {

    private static JwtProperties withSecret(String secret) {
        return new JwtProperties(secret, "iss", "aud", Duration.ofMinutes(15), Duration.ofDays(7));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void secretKey_ausente_impideArrancar(String secret) {
        assertThatThrownBy(() -> withSecret(secret).secretKey())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_SECRET");
    }

    @Test
    void secretKey_noBase64_impideArrancar() {
        assertThatThrownBy(() -> withSecret("no es base64!!").secretKey())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT_SECRET no es Base64 válido");
    }

    @Test
    void secretKey_menorA256Bits_impideArrancar() {
        String weak = Base64.getEncoder().encodeToString(new byte[31]);
        assertThatThrownBy(() -> withSecret(weak).secretKey())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT_SECRET debe tener al menos 256 bits");
    }

    @Test
    void secretKey_de256Bits_esHmacSha256() {
        String ok = Base64.getEncoder().encodeToString(new byte[32]);
        assertThat(withSecret(ok).secretKey().getAlgorithm()).isEqualTo("HmacSHA256");
    }
}
