package com.equipo.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Hash de contraseñas con Argon2id.
 *
 * <p>Parámetros de la OWASP Password Storage Cheat Sheet: 19 MiB de memoria, 2 iteraciones,
 * paralelismo 1, sal de 16 bytes y hash de 32 bytes. Argon2id es resistente a GPU/ASIC por su costo
 * de memoria, a diferencia de BCrypt (4 KiB) o PBKDF2.
 */
@Configuration
public class PasswordConfig {

    static final int SALT_LENGTH = 16;
    static final int HASH_LENGTH = 32;
    static final int PARALLELISM = 1;
    static final int MEMORY_KIB = 19_456;
    static final int ITERATIONS = 2;

    /** Codificador Argon2id. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(SALT_LENGTH, HASH_LENGTH, PARALLELISM, MEMORY_KIB, ITERATIONS);
    }
}
