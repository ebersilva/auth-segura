package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.equipo.auth.support.AbstractApiTest;
import com.equipo.auth.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/** Flujo completo de autenticación de extremo a extremo con la aplicación real y H2. */
class AuthFlowIntegrationTest extends AbstractApiTest {

    @Autowired
    private UserRepository users;

    @Autowired
    private RefreshTokenRepository refreshTokens;

    @Test
    void flujoCompleto_registroLoginPerfilRefreshLogout() throws Exception {
        // 1. Registro: 201, Location y sin datos sensibles
        String username = uniqueUsername();
        postJson("/api/auth/register", registerJson(username, username + "@Ejemplo.com", "  María José  ", PASSWORD))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "/api/users/me"))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(username + "@ejemplo.com"))
                .andExpect(jsonPath("$.displayName").value("María José"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(content().string(not(containsString("password"))))
                .andExpect(content().string(not(containsString("argon2"))));
        assertThat(users.findByUsername(username)).get()
                .satisfies(u -> assertThat(u.getPasswordHash()).startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));

        // 2. Login: tokens sin caché
        String tokens = postJson("/api/auth/login", loginJson(username.toUpperCase(), PASSWORD))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.refreshExpiresIn").value(604_800))
                .andReturn().getResponse().getContentAsString();
        String access1 = read(tokens, "$.accessToken");
        String refresh1 = read(tokens, "$.refreshToken");
        assertThat(refresh1).hasSize(43);

        // 3. Perfil con el access token
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));

        // 4. Refresh: rota el refresh token y emite otro access token
        clock.advance(Duration.ofMinutes(5));
        String rotated = postJson("/api/auth/refresh", refreshJson(refresh1))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String access2 = read(rotated, "$.accessToken");
        String refresh2 = read(rotated, "$.refreshToken");
        assertThat(refresh2).isNotEqualTo(refresh1);
        assertThat(access2).isNotEqualTo(access1);
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access2))
                .andExpect(status().isOk());

        // 5. Logout: 204; después ni el access token ni el refresh token sirven
        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + access2)
                        .contentType(MediaType.APPLICATION_JSON).content(refreshJson(refresh2)))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access2))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", refreshJson(refresh2))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registro_yPerfil_devuelvenElMismoCreatedAt() throws Exception {
        // Arrange: reloj con nanosegundos, como el reloj real del sistema
        clock.set(Instant.parse("2026-11-07T12:00:00.123456789Z"));
        String username = uniqueUsername();
        String registered = postJson("/api/auth/register",
                        registerJson(username, username + "@ejemplo.com", "Ana", PASSWORD))
                .andReturn().getResponse().getContentAsString();
        String access = read(login(username), "$.accessToken");

        // Act
        String profile = mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access))
                .andReturn().getResponse().getContentAsString();

        // Assert
        assertThat(read(profile, "$.createdAt")).isEqualTo(read(registered, "$.createdAt"))
                .isEqualTo("2026-11-07T12:00:00.123Z");
    }

    @Test
    void refreshToken_seGuardaSoloHasheado() throws Exception {
        // Arrange
        String tokens = login(registerUser());
        String refresh = read(tokens, "$.refreshToken");

        // Assert: en la BD no existe el valor en claro, solo su SHA-256
        assertThat(refreshTokens.findAll()).noneMatch(t -> t.getTokenHash().equals(refresh));
        assertThat(refreshTokens.findByTokenHash(new TokenHasher().hash(refresh))).isPresent();
    }

    @Test
    void accessToken_expiraALos15Minutos() throws Exception {
        // Arrange
        String access = read(login(registerUser()), "$.accessToken");

        // Act + Assert: vigente a los 14:59, rechazado a los 15:00
        clock.advance(Duration.ofMinutes(15).minusSeconds(1));
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access)).andExpect(status().isOk());
        clock.advance(Duration.ofSeconds(1));
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"invalid_token\""));
    }

    @Test
    void refreshToken_expiradoDevuelve401() throws Exception {
        // Arrange
        String refresh = read(login(registerUser()), "$.refreshToken");

        // Act + Assert
        clock.advance(Duration.ofDays(7));
        postJson("/api/auth/refresh", refreshJson(refresh))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Token inválido, expirado o revocado"));
    }

    @Test
    void registro_duplicadoDevuelve409Generico() throws Exception {
        // Arrange
        String username = registerUser();

        // Act + Assert: mismo usuario con otro correo, y otro usuario con el mismo correo
        postJson("/api/auth/register", registerJson(username, "otro@ejemplo.com", "Ana", PASSWORD))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value("No fue posible completar el registro con esos datos"));
        postJson("/api/auth/register", registerJson(uniqueUsername(), username + "@ejemplo.com", "Ana", PASSWORD))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value("No fue posible completar el registro con esos datos"));
    }

    @Test
    void registro_contrasenaDebilDevuelve400EnCampoPassword() throws Exception {
        String username = uniqueUsername();
        postJson("/api/auth/register", registerJson(username, username + "@ejemplo.com", "Ana", "password1234"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("password"))
                .andExpect(jsonPath("$.errors[0].message").value("es demasiado común"));
        postJson("/api/auth/register",
                registerJson(username, username + "@ejemplo.com", "Ana", "xx" + username + "-1234"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].message").value("no debe contener el nombre de usuario"));
    }

    @Test
    void registro_variosErroresDevuelveTodosOrdenados() throws Exception {
        postJson("/api/auth/register",
                "{\"username\":\"a\",\"email\":\"x\",\"displayName\":\"\",\"password\":\"corta\"}")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errors.length()").value(4))
                .andExpect(jsonPath("$.errors[0].field").value("displayName"))
                .andExpect(jsonPath("$.errors[1].field").value("email"))
                .andExpect(jsonPath("$.errors[2].field").value("password"))
                .andExpect(jsonPath("$.errors[3].field").value("username"));
    }

    @Test
    void logout_conRefreshDeOtroUsuarioDevuelve401() throws Exception {
        // Arrange
        String accessA = read(login(registerUser()), "$.accessToken");
        String refreshB = read(login(registerUser()), "$.refreshToken");

        // Act + Assert: A no puede cerrar la sesión de B
        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + accessA)
                        .contentType(MediaType.APPLICATION_JSON).content(refreshJson(refreshB)))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", refreshJson(refreshB)).andExpect(status().isOk());
    }

    @Test
    void logout_sinAccessTokenDevuelve401() throws Exception {
        String refresh = read(login(registerUser()), "$.refreshToken");
        postJson("/api/auth/logout", refreshJson(refresh))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"));
    }

    @Test
    void perfil_deUsuarioEliminadoDevuelve401() throws Exception {
        // Arrange
        String username = registerUser();
        String access = read(login(username), "$.accessToken");
        refreshTokens.deleteAll(refreshTokens.findAll().stream()
                .filter(t -> t.getUserId().equals(users.findByUsername(username).orElseThrow().getId())).toList());
        users.delete(users.findByUsername(username).orElseThrow());

        // Act + Assert
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void jsonMalFormado_devuelve400Generico() throws Exception {
        postJson("/api/auth/login", "{\"username\":")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail")
                        .value("El cuerpo no es un JSON válido o contiene campos no permitidos"));
    }

    @Test
    void rutaInexistente_sinTokenDevuelve401() throws Exception {
        mvc.perform(get("/api/admin/usuarios")).andExpect(status().isUnauthorized());
    }
}
