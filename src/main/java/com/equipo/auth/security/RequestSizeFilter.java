package com.equipo.auth.security;

import com.equipo.auth.common.error.ProblemJson;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rechaza cuerpos demasiado grandes antes de leerlos (protección de memoria y CPU).
 *
 * <p>Cuerpos de más de {@code maxBytes} responden 413. Cualquier petición con {@code Transfer-Encoding}
 * responde 411: su tamaño no puede comprobarse antes de leerla, y la combinación
 * {@code Transfer-Encoding} + {@code Content-Length} es el vector de HTTP request smuggling (RFC 9112 §6.1).
 */
public class RequestSizeFilter extends OncePerRequestFilter {

    private final long maxBytes;

    public RequestSizeFilter(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getHeader("Transfer-Encoding") != null) {
            ProblemJson.write(response, 411, "Length Required",
                    "Se requiere la cabecera Content-Length", request.getRequestURI());
            return;
        }
        if (request.getContentLengthLong() > maxBytes) {
            ProblemJson.write(response, 413, "Content Too Large",
                    "El cuerpo excede el tamaño máximo permitido", request.getRequestURI());
            return;
        }
        chain.doFilter(request, response);
    }
}
