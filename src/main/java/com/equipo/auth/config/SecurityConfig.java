package com.equipo.auth.config;

import com.equipo.auth.ratelimit.RateLimitFilter;
import com.equipo.auth.ratelimit.RateLimiter;
import com.equipo.auth.security.ProblemAccessDeniedHandler;
import com.equipo.auth.security.ProblemAuthenticationEntryPoint;
import com.equipo.auth.security.RequestSizeFilter;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Cadena de seguridad HTTP.
 *
 * <ul>
 *   <li>Denegar por defecto: solo register, login y refresh son públicos.</li>
 *   <li>Sesión STATELESS: no hay cookie de sesión; la identidad viaja en el access token.</li>
 *   <li>CSRF deshabilitado: el ataque CSRF explota credenciales que el navegador envía solo
 *       (cookies); un bearer token en la cabecera {@code Authorization} no se envía automáticamente.</li>
 *   <li>Cabeceras: CSP restrictiva, HSTS, nosniff, frame DENY, Referrer-Policy y Permissions-Policy.</li>
 *   <li>Filtros propios antes de la autenticación: tamaño de cuerpo y rate limiting por IP.</li>
 * </ul>
 */
@Configuration
public class SecurityConfig {

    private static final long HSTS_MAX_AGE_SECONDS = 31_536_000;

    /** Cadena de filtros de seguridad. */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
            @Qualifier("ipRateLimiter") RateLimiter ipRateLimiter, HttpSecurityProperties httpProps) {
        ProblemAuthenticationEntryPoint entryPoint = new ProblemAuthenticationEntryPoint();
        ProblemAccessDeniedHandler deniedHandler = new ProblemAccessDeniedHandler();
        http
                // API stateless con bearer token: no hay cookies que un sitio externo pueda reutilizar
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login",
                                "/api/auth/refresh").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint).accessDeniedHandler(deniedHandler))
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"))
                        .frameOptions(f -> f.deny())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true)
                                .maxAgeInSeconds(HSTS_MAX_AGE_SECONDS))
                        .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                        .xssProtection(x -> x.headerValue(HeaderValue.DISABLED))
                        .permissionsPolicyHeader(p -> p.policy("geolocation=(), camera=(), microphone=()")))
                .addFilterBefore(new RequestSizeFilter(httpProps.maxBodyBytes()), BearerTokenAuthenticationFilter.class)
                .addFilterBefore(new RateLimitFilter(ipRateLimiter), RequestSizeFilter.class);
        return http.build();
    }

    /** Convierte el claim {@code roles} en autoridades {@code ROLE_*}. */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    /** CORS solo para los orígenes configurados; nunca {@code *}. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(HttpSecurityProperties httpProps) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(httpProps.corsAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
