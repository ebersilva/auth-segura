package com.equipo.auth.common;

/**
 * Neutraliza la inyección en logs (CWE-117): reemplaza CR, LF y demás caracteres de control para que
 * un valor controlado por el cliente no pueda falsificar líneas de bitácora.
 */
public final class LogSanitizer {

    private LogSanitizer() {
    }

    /**
     * Devuelve el valor apto para registrarse en una sola línea.
     *
     * @param value valor a registrar (puede ser {@code null})
     * @return texto sin caracteres de control
     */
    public static String safe(Object value) {
        if (value == null) {
            return "null";
        }
        String text = String.valueOf(value);
        StringBuilder sb = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            sb.append(Character.isISOControl(c) ? '_' : c);
        }
        return sb.toString().replace("\r", "_").replace("\n", "_");
    }
}
