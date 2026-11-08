package com.equipo.auth.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Reloj del sistema inyectable; los tests lo sustituyen por uno controlable. */
@Configuration
public class ClockConfig {

    /** Reloj UTC del sistema. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
