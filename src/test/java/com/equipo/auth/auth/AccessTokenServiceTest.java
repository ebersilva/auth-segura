package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.equipo.auth.config.JwtConfig;
import com.equipo.auth.config.JwtProperties;
import com.equipo.auth.security.AccessTokenDenylist;
import com.equipo.auth.support.MutableClock;
import com.equipo.auth.user.User;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;

/** Emisión y validación de JWT con la configuración real de Nimbus, sin contexto de Spring. */
class AccessTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    private final MutableClock clock = new MutableClock(NOW);
    private final JwtProperties props = new JwtProperties(Base64.getEncoder().encodeToString(new byte[48]),
            "https://auth-segura.local", "auth-segura-api", Duration.ofMinutes(15), Duration.ofDays(7));
    private final JwtConfig config = new JwtConfig();
    private final SecretKey key = config.jwtSecretKey(props);
    private final AccessTokenDenylist denylist = new AccessTokenDenylist(clock);
    private final JwtDecoder decoder = config.jwtDecoder(key, props, denylist, clock);
    private final AccessTokenService service = new AccessTokenService(config.jwtEncoder(key), props, clock);
    private final User user = new User("ana", "a@b.com", "Ana", "H", NOW);

    @Test
    void issue_incluyeTodosLosClaimsObligatorios() {
        // Act
        Jwt jwt = decoder.decode(service.issue(user));

        // Assert
        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256").containsEntry("typ", "JWT");
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getIssuer().toString()).isEqualTo("https://auth-segura.local");
        assertThat(jwt.getAudience()).containsExactly("auth-segura-api");
        assertThat(jwt.getIssuedAt()).isEqualTo(NOW);
        assertThat(jwt.getExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(jwt.getId()).isNotBlank();
        assertThat(jwt.getClaimAsStringList("roles")).isEqualTo(List.of("USER"));
        assertThat(jwt.getClaimAsString("username")).isEqualTo("ana");
        assertThat(service.ttlSeconds()).isEqualTo(900);
    }

    @Test
    void issue_cadaTokenTieneJtiDistinto() {
        assertThat(decoder.decode(service.issue(user)).getId()).isNotEqualTo(decoder.decode(service.issue(user))
                .getId());
    }

    @Test
    void decode_tokenRevocado_esRechazado() {
        // Arrange
        String token = service.issue(user);
        Jwt jwt = decoder.decode(token);

        // Act
        denylist.revoke(jwt.getId(), jwt.getExpiresAt());

        // Assert
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("Token revocado");
    }

    @Test
    void decode_enElInstanteDeExpiracion_esRechazado() {
        String token = service.issue(user);
        clock.advance(Duration.ofMinutes(15));
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtValidationException.class);
    }
}
