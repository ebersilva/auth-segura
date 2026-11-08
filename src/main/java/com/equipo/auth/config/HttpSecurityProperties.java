package com.equipo.auth.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Políticas HTTP ({@code auth.http.*}).
 *
 * @param corsAllowedOrigins orígenes permitidos por CORS (nunca {@code *})
 * @param maxBodyBytes       tamaño máximo del cuerpo de una petición
 */
@Validated
@ConfigurationProperties("auth.http")
public record HttpSecurityProperties(@NotNull List<String> corsAllowedOrigins, @Min(1) int maxBodyBytes) {

    /** Copia defensiva: la configuración es inmutable una vez cargada. */
    public HttpSecurityProperties {
        corsAllowedOrigins = corsAllowedOrigins == null ? List.of() : List.copyOf(corsAllowedOrigins);
    }
}
