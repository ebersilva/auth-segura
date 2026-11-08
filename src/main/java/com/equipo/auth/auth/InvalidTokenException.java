package com.equipo.auth.auth;

/** Refresh token o sesión inválidos, expirados o revocados. */
public class InvalidTokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Crea la excepción con el mensaje genérico. */
    public InvalidTokenException() {
        super("Token inválido, expirado o revocado");
    }
}
