package com.equipo.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.common.error.ProblemJson;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

class ProblemJsonTest {

    @Test
    void write_escapaComillasBarrasMarcadoYControl() throws Exception {
        // Arrange
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Act
        ProblemJson.write(response, 401, "T", "d", "/a\"b\\c<script>&\n\u0001");

        // Assert
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString()).isEqualTo(
                "{\"type\":\"about:blank\",\"title\":\"T\",\"status\":401,\"detail\":\"d\","
                        + "\"instance\":\"/a\\\"b\\\\c\\u003cscript\\u003e\\u0026\\u000a\\u0001\"}");
    }

    @Test
    void write_valorNulo_emiteNull() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        ProblemJson.write(response, 500, "T", "d", null);
        assertThat(response.getContentAsString()).endsWith("\"instance\":null}");
    }
}
