package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class TokenClaimsTest {

    private static Jwt.Builder jwt() {
        return Jwt.withTokenValue("t").header("alg", "HS256").claim("x", "y");
    }

    @Test
    void userId_subValido_devuelveUuid() {
        UUID id = UUID.randomUUID();
        assertThat(TokenClaims.userId(jwt().subject(id.toString()).build())).isEqualTo(id);
    }

    @Test
    void userId_sinSub_lanzaTokenInvalido() {
        assertThatThrownBy(() -> TokenClaims.userId(jwt().build())).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void userId_subNoUuid_lanzaTokenInvalido() {
        assertThatThrownBy(() -> TokenClaims.userId(jwt().subject("admin").build()))
                .isInstanceOf(InvalidTokenException.class);
    }
}
