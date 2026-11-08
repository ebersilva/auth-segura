package com.equipo.auth.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.equipo.auth.support.AbstractApiTest;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/** Fuerza bruta: límite por usuario, por IP y bloqueo de cuenta. Contexto propio con límites bajos. */
@TestPropertySource(properties = {
    "auth.rate-limit.ip-capacity=30",
    "auth.rate-limit.ip-refill-period=1m",
    "auth.rate-limit.login-capacity=3",
    "auth.rate-limit.login-refill-period=1m",
    "auth.lockout.max-failed-attempts=5",
    "auth.lockout.duration=15m"
})
class BruteForceSecurityTest extends AbstractApiTest {

    @Test
    void loginPorUsuario_superaCapacidad_devuelve429ConRetryAfter() throws Exception {
        // Arrange
        String username = registerUser();

        // Act: 3 intentos permitidos por minuto
        for (int i = 0; i < 3; i++) {
            postJson("/api/auth/login", loginJson(username, "incorrecta-" + i)).andExpect(status().isUnauthorized());
        }

        // Assert: el 4.º se corta antes de verificar la contraseña, aunque sea la correcta
        postJson("/api/auth/login", loginJson(username, PASSWORD))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "20"))
                .andExpect(jsonPath("$.detail").value("Demasiadas solicitudes. Intenta de nuevo más tarde"));

        // Tras la recarga vuelve a permitir
        clock.advance(Duration.ofSeconds(20));
        postJson("/api/auth/login", loginJson(username, PASSWORD)).andExpect(status().isOk());
    }

    @Test
    void bloqueoDeCuenta_tras5Fallos_inclusoConContrasenaCorrecta() throws Exception {
        // Arrange
        String username = registerUser();

        // Act: 5 fallos (avanzando el reloj para no chocar con el limitador por usuario)
        for (int i = 0; i < 5; i++) {
            postJson("/api/auth/login", loginJson(username, "incorrecta-" + i)).andExpect(status().isUnauthorized());
            clock.advance(Duration.ofSeconds(30));
        }

        // Assert: bloqueada, con el MISMO mensaje genérico (no revela el bloqueo)
        postJson("/api/auth/login", loginJson(username, PASSWORD))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Credenciales inválidas"));

        // A los 15 minutos se desbloquea
        clock.advance(Duration.ofMinutes(15));
        postJson("/api/auth/login", loginJson(username, PASSWORD)).andExpect(status().isOk());
    }

    @Test
    void usuarioInexistente_mismaRespuestaQueContrasenaIncorrecta() throws Exception {
        String username = registerUser();
        String wrongPassword = postJson("/api/auth/login", loginJson(username, "incorrecta-123"))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        String unknownUser = postJson("/api/auth/login", loginJson(uniqueUsername(), "incorrecta-123"))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        org.assertj.core.api.Assertions.assertThat(unknownUser).isEqualTo(wrongPassword);
    }

    @Test
    void limitePorIp_noSeEvadeConXForwardedFor() throws Exception {
        // Arrange: IP propia para no interferir con las demás pruebas
        String ip = "203.0.113.7";

        // Act: agota las 30 peticiones cambiando X-Forwarded-For en cada una
        for (int i = 0; i < 30; i++) {
            mvc.perform(post("/api/auth/login").with(r -> {
                r.setRemoteAddr(ip);
                return r;
            }).header("X-Forwarded-For", "10.0.0." + i).contentType(MediaType.APPLICATION_JSON)
                    .content(loginJson(uniqueUsername(), "x")));
        }

        // Assert: la 31.ª se rechaza aunque declare otra IP
        mvc.perform(post("/api/auth/register").with(r -> {
            r.setRemoteAddr(ip);
            return r;
        }).header("X-Forwarded-For", "198.51.100.1").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }
}
