package com.equipo.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.support.MutableClock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class AccessTokenValidatorsTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    private static Jwt.Builder jwt() {
        return Jwt.withTokenValue("t").header("alg", "HS256").subject("s").jti("j").issuedAt(NOW)
                .expiresAt(NOW.plusSeconds(900)).audience(java.util.List.of("api"));
    }

    @Test
    void audience_distinta_falla() {
        assertThat(AccessTokenValidators.audience("api").validate(jwt().build()).hasErrors()).isFalse();
        assertThat(AccessTokenValidators.audience("otra").validate(jwt().build()).hasErrors()).isTrue();
        assertThat(AccessTokenValidators.audience("api").validate(jwt().claims(c -> c.remove("aud")).build())
                .hasErrors()).isTrue();
    }

    @Test
    void requiredClaims_faltaAlguno_falla() {
        assertThat(AccessTokenValidators.requiredClaims().validate(jwt().build()).hasErrors()).isFalse();
        assertThat(AccessTokenValidators.requiredClaims().validate(jwt().claims(c -> c.remove("sub")).build())
                .hasErrors()).isTrue();
        assertThat(AccessTokenValidators.requiredClaims().validate(jwt().claims(c -> c.remove("jti")).build())
                .hasErrors()).isTrue();
        assertThat(AccessTokenValidators.requiredClaims().validate(jwt().claims(c -> c.remove("iat")).build())
                .hasErrors()).isTrue();
    }

    @Test
    void strictExpiry_rechazaEnElInstanteExactoDeExp() {
        MutableClock clock = new MutableClock(NOW.plusSeconds(899));
        assertThat(AccessTokenValidators.strictExpiry(clock).validate(jwt().build()).hasErrors()).isFalse();
        clock.set(NOW.plusSeconds(900));
        assertThat(AccessTokenValidators.strictExpiry(clock).validate(jwt().build()).hasErrors()).isTrue();
        assertThat(AccessTokenValidators.strictExpiry(clock).validate(jwt().claims(c -> c.remove("exp")).build())
                .hasErrors()).isTrue();
    }
}
