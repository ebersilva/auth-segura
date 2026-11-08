package com.equipo.auth.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Políticas de rate limiting ({@code auth.rate-limit.*}).
 *
 * @param ipCapacity         peticiones por IP a {@code /api/auth/**} por periodo
 * @param ipRefillPeriod     periodo en el que se recarga la capacidad por IP
 * @param loginCapacity      intentos de login por usuario por periodo
 * @param loginRefillPeriod  periodo en el que se recarga la capacidad por usuario
 */
@Validated
@ConfigurationProperties("auth.rate-limit")
public record RateLimitProperties(
        @Min(1) int ipCapacity,
        @NotNull Duration ipRefillPeriod,
        @Min(1) int loginCapacity,
        @NotNull Duration loginRefillPeriod) {
}
