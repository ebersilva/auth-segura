package com.equipo.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.common.error.GlobalExceptionHandler;
import com.equipo.auth.security.ProblemAccessDeniedHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.ProblemDetail;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

class GlobalExceptionHandlerTest {

    @Test
    void handleUnexpected_devuelve500SinDetallesInternos() {
        // Arrange: una excepción con información sensible
        RuntimeException ex = new IllegalStateException("SQL: select * from users where password='x'");

        // Act
        ProblemDetail problem = new GlobalExceptionHandler().handleUnexpected(ex);

        // Assert
        assertThat(problem.getStatus()).isEqualTo(500);
        assertThat(problem.getDetail()).isEqualTo("Error interno del servidor");
        assertThat(problem.toString()).doesNotContain("SQL", "password", "IllegalStateException");
    }

    @Test
    void accessDenied_devuelve403ProblemJson() throws Exception {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin");
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Act
        new ProblemAccessDeniedHandler().handle(request, response, new AccessDeniedException("rol"));

        // Assert
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("\"detail\":\"No tienes permiso para este recurso\"")
                .doesNotContain("rol\"");
    }
}
