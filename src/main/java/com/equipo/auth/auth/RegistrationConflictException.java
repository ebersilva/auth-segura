package com.equipo.auth.auth;

/** Usuario o correo ya registrados. El mensaje no indica cuál de los dos para limitar la enumeración. */
public class RegistrationConflictException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Crea la excepción con el mensaje genérico. */
    public RegistrationConflictException() {
        super("No fue posible completar el registro con esos datos");
    }
}
