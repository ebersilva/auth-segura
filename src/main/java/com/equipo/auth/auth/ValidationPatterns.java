package com.equipo.auth.auth;

/** Allowlists de la validación de entrada, compartidas por los DTOs. */
public final class ValidationPatterns {

    /** Letras ASCII, dígitos, punto, guion y guion bajo; 3 a 30 caracteres. */
    public static final String USERNAME = "^[a-z0-9._-]{3,30}$";

    /** Letras Unicode, espacio, punto, apóstrofo y guion; 1 a 60 caracteres. Excluye {@code < > " & ;}. */
    public static final String DISPLAY_NAME = "^[\\p{L}\\p{M} .'-]{1,60}$";

    /** Correo sin espacios ni caracteres de marcado o comillas. */
    public static final String EMAIL = "^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,185}\\.[A-Za-z]{2,63}$";

    /** Refresh token: 32 bytes en Base64URL sin relleno (43 caracteres). */
    public static final String REFRESH_TOKEN = "^[A-Za-z0-9_-]{43}$";

    private ValidationPatterns() {
    }
}
