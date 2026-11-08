package com.equipo.auth.ratelimit;

import com.equipo.auth.config.RateLimitProperties;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Instancias de rate limiter según las políticas configuradas. */
@Configuration
public class RateLimitConfig {

    /** Limitador por IP para todo {@code /api/auth/**}. */
    @Bean
    public RateLimiter ipRateLimiter(RateLimitProperties props, Clock clock) {
        return new RateLimiter(props.ipCapacity(), props.ipRefillPeriod(), clock);
    }

    /** Limitador por usuario para el login. */
    @Bean
    public RateLimiter loginRateLimiter(RateLimitProperties props, Clock clock) {
        return new RateLimiter(props.loginCapacity(), props.loginRefillPeriod(), clock);
    }
}
