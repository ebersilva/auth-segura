package com.equipo.auth.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Bloqueo temporal de cuentas ({@code auth.lockout.*}).
 *
 * @param maxFailedAttempts intentos fallidos consecutivos que provocan el bloqueo
 * @param duration          duración del bloqueo
 */
@Validated
@ConfigurationProperties("auth.lockout")
public record LockoutProperties(@Min(1) int maxFailedAttempts, @NotNull Duration duration) {
}
