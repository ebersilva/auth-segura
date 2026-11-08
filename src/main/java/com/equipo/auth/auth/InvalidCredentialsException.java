package com.equipo.auth.auth;

/** Login fallido. El mensaje es siempre el mismo para no revelar la causa (usuario, contraseña o bloqueo). */
public class InvalidCredentialsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Crea la excepción con el mensaje genérico. */
    public InvalidCredentialsException() {
        super("Credenciales inválidas");
    }
}
