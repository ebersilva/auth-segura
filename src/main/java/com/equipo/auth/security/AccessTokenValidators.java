package com.equipo.auth.security;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Validadores adicionales de claims para los access tokens. */
public final class AccessTokenValidators {

    private AccessTokenValidators() {
    }

    /** Exige que {@code aud} contenga la audiencia de esta API. */
    public static OAuth2TokenValidator<Jwt> audience(String expected) {
        return jwt -> {
            List<String> aud = jwt.getAudience();
            return aud != null && aud.contains(expected) ? OAuth2TokenValidatorResult.success()
                    : failure("Audiencia inválida");
        };
    }

    /** Exige los claims {@code sub}, {@code jti} e {@code iat}. */
    public static OAuth2TokenValidator<Jwt> requiredClaims() {
        return jwt -> jwt.getSubject() != null && jwt.getId() != null && jwt.getIssuedAt() != null
                ? OAuth2TokenValidatorResult.success() : failure("Faltan claims obligatorios");
    }

    /**
     * Exige que el instante actual sea estrictamente anterior a {@code exp} (RFC 7519 §4.1.4).
     *
     * <p>{@code JwtTimestampValidator} de Spring acepta el token en el instante exacto de {@code exp}
     * (compara con {@code isAfter}); este validador cierra ese margen.
     */
    public static OAuth2TokenValidator<Jwt> strictExpiry(Clock clock) {
        return jwt -> {
            Instant exp = jwt.getExpiresAt();
            return exp != null && clock.instant().isBefore(exp) ? OAuth2TokenValidatorResult.success()
                    : failure("Token expirado");
        };
    }

    /** Rechaza tokens revocados por logout. */
    public static OAuth2TokenValidator<Jwt> notRevoked(AccessTokenDenylist denylist) {
        return jwt -> denylist.isRevoked(jwt.getId()) ? failure("Token revocado")
                : OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult failure(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null));
    }
}
