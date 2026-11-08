package com.equipo.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.equipo.auth.auth.RefreshTokenRepository;
import com.equipo.auth.auth.TokenHasher;
import com.equipo.auth.support.AbstractApiTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

/** Robo y reutilización de refresh tokens. */
class RefreshTokenReuseSecurityTest extends AbstractApiTest {

    @Autowired
    private RefreshTokenRepository repository;

    @Test
    void reutilizacion_revocaTodaLaFamilia() throws Exception {
        // Arrange: la víctima rota su token; el atacante tiene una copia del token anterior
        String stolen = read(login(registerUser()), "$.refreshToken");
        String victimNew = read(postJson("/api/auth/refresh", refreshJson(stolen))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(), "$.refreshToken");

        // Act: el atacante usa el token robado
        postJson("/api/auth/refresh", refreshJson(stolen)).andExpect(status().isUnauthorized());

        // Assert: la familia completa quedó revocada (también el token vigente de la víctima)
        postJson("/api/auth/refresh", refreshJson(victimNew)).andExpect(status().isUnauthorized());
        var family = repository.findByTokenHash(new TokenHasher().hash(victimNew)).orElseThrow().getFamilyId();
        assertThat(repository.findByFamilyId(family)).hasSize(2).allMatch(t -> t.isRevoked());
    }

    @Test
    void reutilizacion_noAfectaOtrasSesionesDelMismoUsuario() throws Exception {
        // Arrange: dos sesiones (dos logins = dos familias)
        String username = registerUser();
        String sessionA = read(login(username), "$.refreshToken");
        String sessionB = read(login(username), "$.refreshToken");
        postJson("/api/auth/refresh", refreshJson(sessionA)).andExpect(status().isOk());

        // Act: reutilización en la sesión A
        postJson("/api/auth/refresh", refreshJson(sessionA)).andExpect(status().isUnauthorized());

        // Assert: la sesión B sigue viva
        postJson("/api/auth/refresh", refreshJson(sessionB)).andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "token-inventado-de-43-caracteres-xxxxxxxxxx"})
    void tokenInventado_devuelve401(String token) throws Exception {
        postJson("/api/auth/refresh", refreshJson(token)).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"corto", "' OR '1'='1' OR 'aaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "<script>alert(1)</script>xxxxxxxxxxxxxxxxx"})
    void tokenConFormatoInvalido_devuelve400(String token) throws Exception {
        postJson("/api/auth/refresh", refreshJson(token)).andExpect(status().isBadRequest());
    }
}
