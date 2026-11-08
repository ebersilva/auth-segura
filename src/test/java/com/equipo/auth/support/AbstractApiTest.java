package com.equipo.auth.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/** Base de las pruebas de contexto completo: HTTP → filtros de seguridad → controlador → JPA → H2. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestClockConfig.class)
public abstract class AbstractApiTest {

    /** Contraseña ficticia de las pruebas (solo existe en la H2 en memoria de cada ejecución). */
    protected static final String PASSWORD = "Correcta-Caballo-Bateria-42"; // gitleaks:allow

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected MutableClock clock;

    @BeforeEach
    void resetClock() {
        clock.set(TestClockConfig.START);
    }

    /** Usuario único por prueba (el contexto y la BD se comparten entre clases). */
    protected static String uniqueUsername() {
        return "u" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    protected ResultActions postJson(String url, String json) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    protected static String registerJson(String username, String email, String displayName, String password) {
        return """
                {"username":%s,"email":%s,"displayName":%s,"password":%s}
                """.formatted(q(username), q(email), q(displayName), q(password));
    }

    protected static String loginJson(String username, String password) {
        return "{\"username\":%s,\"password\":%s}".formatted(q(username), q(password));
    }

    protected static String refreshJson(String refreshToken) {
        return "{\"refreshToken\":%s}".formatted(q(refreshToken));
    }

    /** Registra un usuario válido y devuelve su nombre. */
    protected String registerUser() throws Exception {
        String username = uniqueUsername();
        postJson("/api/auth/register", registerJson(username, username + "@ejemplo.com", "Ana López", PASSWORD))
                .andExpect(status().isCreated());
        return username;
    }

    /** Inicia sesión y devuelve el cuerpo JSON con los tokens. */
    protected String login(String username) throws Exception {
        return postJson("/api/auth/login", loginJson(username, PASSWORD))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    protected static String read(String json, String path) {
        return JsonPath.read(json, path);
    }

    /** Literal JSON con escape mínimo para los payloads de prueba. */
    protected static String q(String value) {
        if (value == null) {
            return "null";
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
