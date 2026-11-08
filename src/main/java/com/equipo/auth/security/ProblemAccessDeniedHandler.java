package com.equipo.auth.security;

import com.equipo.auth.common.error.ProblemJson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/** Responde 403 en formato RFC 9457. */
public class ProblemAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        ProblemJson.write(response, 403, "Forbidden", "No tienes permiso para este recurso",
                request.getRequestURI());
    }
}
