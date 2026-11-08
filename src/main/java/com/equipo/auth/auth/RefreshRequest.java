package com.equipo.auth.auth;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Petición con un refresh token (usada por {@code /refresh} y {@code /logout}).
 *
 * @param refreshToken valor opaco recibido en el login
 */
public record RefreshRequest(
        @NotNull(message = "es obligatorio")
        @Pattern(regexp = ValidationPatterns.REFRESH_TOKEN, message = "formato inválido")
        String refreshToken) {

    @Override
    public String toString() {
        return "RefreshRequest[refreshToken=****]";
    }
}
