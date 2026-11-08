package com.equipo.auth.auth;

import java.util.UUID;
import org.springframework.security.oauth2.jwt.Jwt;

/** Lectura defensiva de claims del access token ya validado. */
public final class TokenClaims {

    private TokenClaims() {
    }

    /**
     * Identificador del usuario ({@code sub}).
     *
     * @param jwt token validado
     * @return id del usuario
     * @throws InvalidTokenException si falta o no es un UUID
     */
    public static UUID userId(Jwt jwt) {
        String subject = jwt.getSubject();
        if (subject == null) {
            throw new InvalidTokenException();
        }
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException();
        }
    }
}
