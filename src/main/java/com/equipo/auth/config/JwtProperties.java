package com.equipo.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuración de los tokens JWT ({@code auth.jwt.*}).
 *
 * @param secret          clave HMAC en Base64 (variable de entorno {@code JWT_SECRET}), mínimo 256 bits
 * @param issuer          emisor ({@code iss}) que se escribe y se exige al validar
 * @param audience        audiencia ({@code aud}) que se escribe y se exige al validar
 * @param accessTokenTtl  vigencia del access token
 * @param refreshTokenTtl vigencia del refresh token
 */
@Validated
@ConfigurationProperties("auth.jwt")
public record JwtProperties(
        String secret,
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration refreshTokenTtl) {

    /** Longitud mínima de la clave HS256 (RFC 7518 §3.2): 256 bits. */
    static final int MIN_SECRET_BYTES = 32;

    /**
     * Decodifica y valida la clave de firma.
     *
     * @return clave HMAC-SHA256
     * @throws IllegalStateException si el secreto falta, no es Base64 o es menor a 256 bits;
     *                               así la aplicación no arranca con una clave débil
     */
    public SecretKey secretKey() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("Falta la variable de entorno JWT_SECRET (Base64, mínimo 256 bits)");
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(secret.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT_SECRET no es Base64 válido", e);
        }
        if (bytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("JWT_SECRET debe tener al menos 256 bits");
        }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }
}
