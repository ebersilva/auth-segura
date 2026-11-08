package com.equipo.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.AuthSeguraApplication;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

/** La aplicación no debe arrancar con un secreto JWT ausente o débil (fail fast). */
class StartupWithoutSecretTest {

    private static Throwable startWith(String secretArg) {
        SpringApplication app = new SpringApplication(AuthSeguraApplication.class);
        // Base propia: al fallar el arranque, el create-drop no debe tocar la base de otras pruebas
        String db = "--spring.datasource.url=jdbc:h2:mem:startup-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
        try (ConfigurableApplicationContext ctx = app.run("--server.port=0", db, secretArg)) {
            return null;
        } catch (RuntimeException e) {
            return e;
        }
    }

    private static Throwable rootCause(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    @Test
    void arranque_sinJwtSecret_falla() {
        Throwable error = startWith("--auth.jwt.secret=");
        assertThat(error).isNotNull();
        assertThat(rootCause(error)).hasMessageContaining("Falta la variable de entorno JWT_SECRET");
    }

    @Test
    void arranque_conSecretoCorto_falla() {
        Throwable error = startWith("--auth.jwt.secret=c2VjcmV0bw==");
        assertThat(rootCause(error)).hasMessage("JWT_SECRET debe tener al menos 256 bits");
    }
}
