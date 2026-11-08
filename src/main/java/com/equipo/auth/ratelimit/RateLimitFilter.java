package com.equipo.auth.ratelimit;

import com.equipo.auth.common.LogSanitizer;
import com.equipo.auth.common.error.ProblemJson;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Limita por IP las peticiones a {@code /api/auth/**}, antes de la autenticación y del parseo del cuerpo.
 *
 * <p>La IP es {@code request.getRemoteAddr()}. No se usa {@code X-Forwarded-For}: el cliente puede
 * falsificarlo para obtener una cubeta nueva en cada petición. Detrás de un proxy de confianza se
 * configura {@code server.forward-headers-strategy=native} para que el contenedor resuelva la IP real.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(RateLimitFilter.class);
    private static final String PROTECTED_PREFIX = "/api/auth/";

    private final RateLimiter ipRateLimiter;

    public RateLimitFilter(RateLimiter ipRateLimiter) {
        this.ipRateLimiter = ipRateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(PROTECTED_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RateLimiter.Decision decision = ipRateLimiter.tryAcquire("ip:" + request.getRemoteAddr());
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        LOG.warn("SECURITY ip_rate_limited ip={}", LogSanitizer.safe(request.getRemoteAddr()));
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(decision.retryAfterSeconds()));
        ProblemJson.write(response, 429, "Too Many Requests",
                "Demasiadas solicitudes. Intenta de nuevo más tarde", request.getRequestURI());
    }
}
