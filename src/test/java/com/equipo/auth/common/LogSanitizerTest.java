package com.equipo.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void safe_reemplazaSaltosDeLineaParaEvitarLineasFalsas() {
        // Un atacante intenta inyectar una línea de log falsa
        String forged = "ana\r\nSECURITY login_ok user=admin";
        assertThat(LogSanitizer.safe(forged)).isEqualTo("ana__SECURITY login_ok user=admin").doesNotContain("\n");
    }

    @Test
    void safe_reemplazaOtrosCaracteresDeControl() {
        assertThat(LogSanitizer.safe("a\tb\u0000c\u001bd")).isEqualTo("a_b_c_d");
    }

    @Test
    void safe_nuloYObjetos() {
        assertThat(LogSanitizer.safe(null)).isEqualTo("null");
        assertThat(LogSanitizer.safe(42)).isEqualTo("42");
        assertThat(LogSanitizer.safe("José Ñúñez")).isEqualTo("José Ñúñez");
    }
}
