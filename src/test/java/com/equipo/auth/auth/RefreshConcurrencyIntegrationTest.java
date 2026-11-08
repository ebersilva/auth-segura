package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.equipo.auth.support.AbstractApiTest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/** Dos renovaciones simultáneas con el mismo refresh token: solo una puede obtener tokens nuevos. */
class RefreshConcurrencyIntegrationTest extends AbstractApiTest {

    @Test
    void refreshSimultaneo_soloUnoTieneExito() throws Exception {
        // Arrange
        String refresh = read(login(registerUser()), "$.refreshToken");
        Callable<Integer> attempt = () -> postJson("/api/auth/refresh", refreshJson(refresh))
                .andReturn().getResponse().getStatus();

        // Act
        List<Integer> statuses = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                futures.add(pool.submit(attempt));
            }
            for (Future<Integer> f : futures) {
                statuses.add(f.get());
            }
        }

        // Assert
        assertThat(statuses).containsOnly(200, 401);
        assertThat(statuses).filteredOn(s -> s == 200).hasSize(1);
    }
}
