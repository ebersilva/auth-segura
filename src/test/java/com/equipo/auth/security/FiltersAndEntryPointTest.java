package com.equipo.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.ratelimit.RateLimitFilter;
import com.equipo.auth.ratelimit.RateLimiter;
import com.equipo.auth.support.MutableClock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

/** Pruebas unitarias de los filtros propios y del entry point (sin contexto de Spring). */
class FiltersAndEntryPointTest {

    private static MockHttpServletRequest post(String uri, byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
        request.setContent(body);
        return request;
    }

    @Test
    void requestSize_enElLimite_continua() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RequestSizeFilter(10).doFilter(post("/api/auth/login", new byte[10]), response, chain);
        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void requestSize_unByteDeMas_responde413SinContinuar() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RequestSizeFilter(10).doFilter(post("/api/auth/login", new byte[11]), response, chain);
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).contains("tamaño máximo");
    }

    @Test
    void requestSize_chunkedSinLongitud_responde411() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.addHeader("Transfer-Encoding", "chunked");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RequestSizeFilter(10).doFilter(request, response, chain);
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(411);
    }

    @Test
    void requestSize_transferEncodingConContentLength_responde411() throws Exception {
        // Ambas cabeceras a la vez: vector de request smuggling (RFC 9112 §6.1)
        MockHttpServletRequest request = post("/api/auth/login", new byte[0]);
        request.addHeader("Transfer-Encoding", "chunked");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RequestSizeFilter(10).doFilter(request, response, chain);
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(411);
    }

    @Test
    void requestSize_getSinCuerpo_continua() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        new RequestSizeFilter(10).doFilter(new MockHttpServletRequest("GET", "/api/users/me"),
                new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void rateLimitFilter_soloAplicaAAuthYResponde429ConRetryAfter() throws Exception {
        // Arrange: 1 petición por minuto
        RateLimitFilter filter = new RateLimitFilter(new RateLimiter(1, Duration.ofMinutes(1),
                new MutableClock(Instant.parse("2026-11-07T12:00:00Z"))));
        MockFilterChain first = new MockFilterChain();
        filter.doFilter(post("/api/auth/login", new byte[0]), new MockHttpServletResponse(), first);

        // Act
        MockFilterChain second = new MockFilterChain();
        MockHttpServletResponse limited = new MockHttpServletResponse();
        filter.doFilter(post("/api/auth/login", new byte[0]), limited, second);
        MockFilterChain other = new MockFilterChain();
        filter.doFilter(new MockHttpServletRequest("GET", "/api/users/me"), new MockHttpServletResponse(), other);

        // Assert
        assertThat(first.getRequest()).isNotNull();
        assertThat(second.getRequest()).isNull();
        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getHeader("Retry-After")).isEqualTo("60");
        assertThat(other.getRequest()).as("rutas fuera de /api/auth/ no consumen fichas").isNotNull();
    }

    @Test
    void entryPoint_sinToken_bearerSimple() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ProblemAuthenticationEntryPoint().commence(new MockHttpServletRequest("GET", "/api/users/me"), response,
                new BadCredentialsException("x"));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(response.getContentAsString()).contains("Se requiere un token de acceso válido");
    }

    @Test
    void entryPoint_conTokenInvalido_indicaInvalidTokenSinCausa() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
        request.addHeader("Authorization", "Bearer abc");
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ProblemAuthenticationEntryPoint().commence(request, response, new BadCredentialsException("firma"));
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"invalid_token\"");
        assertThat(response.getContentAsString()).doesNotContain("firma");
    }
}
