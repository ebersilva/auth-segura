package com.equipo.auth.support;

import java.time.Instant;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** Sustituye el reloj del sistema por uno controlable en las pruebas de contexto completo. */
@TestConfiguration
public class TestClockConfig {

    public static final Instant START = Instant.parse("2026-11-07T12:00:00Z");

    @Bean
    @Primary
    public MutableClock testClock() {
        return new MutableClock(START);
    }
}
