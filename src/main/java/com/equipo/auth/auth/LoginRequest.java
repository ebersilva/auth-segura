package com.equipo.auth.auth;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Locale;

/**
 * Credenciales de login.
 *
 * @param username usuario (se normaliza a minúsculas)
 * @param password contraseña
 */
public record LoginRequest(
        @NotNull(message = "es obligatorio")
        @Pattern(regexp = ValidationPatterns.USERNAME, message = "formato inválido")
        String username,

        @NotNull(message = "es obligatorio")
        @Size(min = 1, max = 128, message = "debe tener entre 1 y 128 caracteres")
        String password) {

    /** Normaliza el usuario igual que en el registro. */
    public LoginRequest {
        username = username == null ? null : username.strip().toLowerCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return "LoginRequest[username=" + username + ", password=****]";
    }
}
