package com.equipo.auth.security;

import com.equipo.auth.common.error.ProblemJson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Responde 401 en formato RFC 9457 y con {@code WWW-Authenticate: Bearer} (RFC 6750) cuando falta el
 * token o no es válido. No incluye la causa concreta (firma, expiración, emisor) para no orientar al atacante.
 */
public class ProblemAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        boolean tokenPresent = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                tokenPresent ? "Bearer error=\"invalid_token\"" : "Bearer");
        ProblemJson.write(response, 401, "Unauthorized", "Se requiere un token de acceso válido",
                request.getRequestURI());
    }
}
