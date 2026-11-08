package com.equipo.auth.config;

import com.equipo.auth.security.AccessTokenDenylist;
import com.equipo.auth.security.AccessTokenValidators;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.time.Clock;
import java.time.Duration;
import javax.crypto.SecretKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Emisión y validación de JWT con Nimbus (HS256).
 *
 * <p>El decoder solo acepta HS256: un token con {@code alg=none} u otro algoritmo se rechaza antes de
 * evaluar sus claims (defensa ante algorithm confusion).
 */
@Configuration
public class JwtConfig {

    /** Clave de firma. Falla al arrancar si {@code JWT_SECRET} falta o es débil. */
    @Bean
    public SecretKey jwtSecretKey(JwtProperties properties) {
        return properties.secretKey();
    }

    /** Codificador que firma los access tokens. */
    @Bean
    public JwtEncoder jwtEncoder(SecretKey jwtSecretKey) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtSecretKey));
    }

    /**
     * Decodificador con validación de firma (HS256), expiración sin tolerancia adicional, emisor,
     * audiencia, claims obligatorios y lista de revocación.
     */
    @Bean
    public JwtDecoder jwtDecoder(SecretKey jwtSecretKey, JwtProperties properties, AccessTokenDenylist denylist,
            Clock clock) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSecretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        JwtTimestampValidator timestamps = new JwtTimestampValidator(Duration.ZERO);
        timestamps.setClock(clock);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                timestamps,
                AccessTokenValidators.strictExpiry(clock),
                new JwtIssuerValidator(properties.issuer()),
                AccessTokenValidators.audience(properties.audience()),
                AccessTokenValidators.requiredClaims(),
                AccessTokenValidators.notRevoked(denylist)));
        return decoder;
    }
}
