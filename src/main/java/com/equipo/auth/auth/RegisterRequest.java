package com.equipo.auth.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Locale;

/**
 * Datos de registro. El esquema usa allowlists: cualquier carácter fuera de ellas se rechaza con 400
 * antes de llegar al servicio o a la base de datos.
 *
 * @param username    usuario (se normaliza a minúsculas)
 * @param email       correo (se normaliza a minúsculas)
 * @param displayName nombre visible
 * @param password    contraseña en claro (solo vive en memoria durante la petición)
 */
public record RegisterRequest(
        @NotNull(message = "es obligatorio")
        @Pattern(regexp = ValidationPatterns.USERNAME,
                message = "debe tener de 3 a 30 caracteres: letras, dígitos, punto, guion o guion bajo")
        String username,

        @NotNull(message = "es obligatorio")
        @Size(max = 254, message = "no debe exceder 254 caracteres")
        @Email(regexp = ValidationPatterns.EMAIL, message = "no es un correo válido")
        String email,

        @NotNull(message = "es obligatorio")
        @Pattern(regexp = ValidationPatterns.DISPLAY_NAME,
                message = "debe tener de 1 a 60 caracteres: letras, espacios, punto, apóstrofo o guion")
        String displayName,

        @NotNull(message = "es obligatorio")
        @Size(min = 12, max = 128, message = "debe tener entre 12 y 128 caracteres")
        String password) {

    /** Normaliza usuario, correo y nombre antes de validar. La contraseña no se modifica. */
    public RegisterRequest {
        username = username == null ? null : username.strip().toLowerCase(Locale.ROOT);
        email = email == null ? null : email.strip().toLowerCase(Locale.ROOT);
        displayName = displayName == null ? null : displayName.strip();
    }

    @Override
    public String toString() {
        return "RegisterRequest[username=" + username + ", password=****]";
    }
}
