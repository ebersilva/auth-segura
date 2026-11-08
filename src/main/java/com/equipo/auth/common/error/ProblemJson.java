package com.equipo.auth.common.error;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Escribe respuestas RFC 9457 desde filtros, donde todavía no actúa el {@code GlobalExceptionHandler}.
 *
 * <p>Los valores se escapan como JSON y los caracteres {@code < > &} se emiten como {@code \\uXXXX},
 * de modo que una URI maliciosa reflejada en {@code instance} no puede inyectar marcado.
 */
public final class ProblemJson {

    private ProblemJson() {
    }

    /**
     * Escribe un problem+json en la respuesta.
     *
     * @param response respuesta HTTP
     * @param status   código de estado
     * @param title    título corto
     * @param detail   detalle para el cliente (sin información interna)
     * @param instance URI de la petición
     * @throws IOException si falla la escritura
     */
    public static void write(HttpServletResponse response, int status, String title, String detail,
            String instance) throws IOException {
        response.setStatus(status);
        response.setContentType("application/problem+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        String body = "{\"type\":\"about:blank\",\"title\":" + quote(title)
                + ",\"status\":" + status
                + ",\"detail\":" + quote(detail)
                + ",\"instance\":" + quote(instance) + "}";
        response.getWriter().write(body);
    }

    /** Convierte un texto en literal JSON seguro. */
    static String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 2).append('"');
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '<', '>', '&' -> sb.append(String.format("\\u%04x", (int) c));
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
