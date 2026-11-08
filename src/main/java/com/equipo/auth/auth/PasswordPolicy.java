package com.equipo.auth.auth;

import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Política de contraseñas basada en NIST SP 800-63B: longitud (12 a 128, validada en el DTO),
 * lista de contraseñas comunes y prohibición de contener el nombre de usuario. No impone reglas de
 * composición (mayúsculas, símbolos), que NIST desaconseja.
 */
@Component
public class PasswordPolicy {

    /** Muestra de contraseñas comunes de 12+ caracteres. En producción: lista completa (p. ej. HIBP). */
    private static final Set<String> COMMON = Set.of(
            "123456789012", "password1234", "contraseña123", "qwertyuiop12", "administrator",
            "iloveyou1234", "passw0rd1234", "welcome12345", "111111111111", "abc123456789",
            // Lista pública de contraseñas comunes, no son secretos
            "qwerty123456", "contrasena123", "letmein12345", "password12345", "1234567890ab"); // gitleaks:allow

    /**
     * Valida la contraseña.
     *
     * @param password contraseña ya validada por longitud
     * @param username usuario normalizado
     * @throws WeakPasswordException si es común o contiene el usuario
     */
    public void validate(String password, String username) {
        String lower = password.toLowerCase(Locale.ROOT);
        if (COMMON.contains(lower)) {
            throw new WeakPasswordException("es demasiado común");
        }
        if (lower.contains(username)) {
            throw new WeakPasswordException("no debe contener el nombre de usuario");
        }
    }
}
