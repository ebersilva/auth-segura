package com.equipo.auth.security;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/** Inyección SQL, XSS, mass assignment, tamaño de cuerpo y cabeceras de seguridad. */
class InjectionAndXssSecurityTest extends AbstractApiTest {

    private static final String[] SQLI = {
        "' OR '1'='1", "admin'--", "admin' #", "'; DROP TABLE users;--", "' UNION SELECT * FROM users--",
        "1' AND SLEEP(5)--", "\" OR \"\"=\"", "admin'/*"
    };

    @Autowired
    private UserRepository users;

    @ParameterizedTest
    @ValueSource(strings = {"' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "' UNION SELECT * FROM users--",
        "1' AND SLEEP(5)--", "admin'/*"})
    void sqlInjection_enUsernameDeLogin_esRechazadaPorEsquema(String payload) throws Exception {
        long before = users.count();
        postJson("/api/auth/login", loginJson(payload, PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("username"))
                .andExpect(content().string(not(containsString("SQL"))));
        assertThat(users.count()).isEqualTo(before);
    }

    @Test
    void sqlInjection_enPassword_noAutentica() throws Exception {
        // La contraseña admite cualquier carácter (no se valida con allowlist), pero nunca toca SQL:
        // se compara con Argon2 contra el hash del usuario.
        String username = registerUser();
        for (String payload : SQLI) {
            postJson("/api/auth/login", loginJson(username, payload))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.detail").value("Credenciales inválidas"));
            postJson("/api/auth/login", loginJson(username, PASSWORD)).andExpect(status().isOk());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"' OR '1'='1", "a@b.com' OR 1=1--", "x@y.com'; DROP TABLE users;--",
        "\"a\"@b.com", "a@b.com\nBcc: c@d.com"})
    void sqlInjection_enEmailDeRegistro_esRechazada(String payload) throws Exception {
        long before = users.count();
        postJson("/api/auth/register", registerJson(uniqueUsername(), payload, "Ana", PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("email"));
        assertThat(users.count()).isEqualTo(before);
    }

    @Test
    void sqlInjection_enUsernameDeRegistro_esRechazada() throws Exception {
        for (String payload : SQLI) {
            postJson("/api/auth/register", registerJson(payload, "ana@ejemplo.com", "Ana", PASSWORD))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors[0].field").value("username"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
        "&lt;script&gt;", "Ana\"><svg/onload=alert(1)>", "{{7*7}}", "${7*7}", "Ana; DROP TABLE users"})
    void xss_enDisplayName_esRechazado(String payload) throws Exception {
        postJson("/api/auth/register", registerJson(uniqueUsername(), uniqueUsername() + "@ejemplo.com", payload,
                        PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("displayName"))
                // El valor rechazado nunca se refleja en la respuesta
                .andExpect(content().string(not(containsString("<"))))
                .andExpect(content().string(not(containsString("alert"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"<script>", "ana<b>", "ana\"onmouseover", "ana%3Cscript"})
    void xss_enUsername_esRechazado(String payload) throws Exception {
        postJson("/api/auth/register", registerJson(payload, "ana@ejemplo.com", "Ana", PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("<"))));
    }

    @Test
    void xss_enRutaReflejadaEnError_seEscapa() throws Exception {
        // La URI aparece en "instance" de las respuestas de los filtros: no debe poder inyectar marcado
        mvc.perform(get("/api/users/<script>alert(1)</script>"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(not(containsString("<script>"))));
    }

    @Test
    void nombresInternacionales_sonAceptados() throws Exception {
        // La allowlist no debe rechazar nombres legítimos
        postJson("/api/auth/register", registerJson(uniqueUsername(), uniqueUsername() + "@ejemplo.com",
                        "José Ñúñez-O'Connor", PASSWORD))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.displayName").value("José Ñúñez-O'Connor"));
    }

    @Test
    void massAssignment_rolAdmin_esRechazado() throws Exception {
        String username = uniqueUsername();
        String json = registerJson(username, username + "@ejemplo.com", "Ana", PASSWORD)
                .replace("}", ",\"role\":\"ADMIN\"}");
        postJson("/api/auth/register", json).andExpect(status().isBadRequest());
        assertThat(users.findByUsername(username)).isEmpty();
    }

    @Test
    void campoDesconocido_esRechazado() throws Exception {
        postJson("/api/auth/login", "{\"username\":\"ana\",\"password\":\"x\",\"isAdmin\":true}")
                .andExpect(status().isBadRequest());
    }

    @Test
    void cuerpoMayorA4Kb_devuelve413() throws Exception {
        String big = "a".repeat(5000);
        postJson("/api/auth/login", loginJson("ana", big))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void cuerpoChunkedSinLongitud_devuelve411() throws Exception {
        mvc.perform(post("/api/auth/login").header("Transfer-Encoding", "chunked")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isLengthRequired());
    }

    @Test
    void respuestas_incluyenCabecerasDeSeguridad() throws Exception {
        String access = read(login(registerUser()), "$.accessToken");
        mvc.perform(get("/api/users/me").secure(true).header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void cors_origenNoPermitido_esRechazado() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options("/api/auth/login")
                        .header("Origin", "https://atacante.example")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options("/api/auth/login")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }
}
