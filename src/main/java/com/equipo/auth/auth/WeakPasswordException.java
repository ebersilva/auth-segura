package com.equipo.auth.auth;

/** La contraseña cumple el esquema pero no la política (común o contiene el usuario). */
public class WeakPasswordException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Crea la excepción.
     *
     * @param message motivo para el cliente
     */
    public WeakPasswordException(String message) {
        super(message);
    }
}
