package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenHasherTest {

    private final TokenHasher hasher = new TokenHasher();

    @Test
    void newToken_tiene43CaracteresBase64UrlYEsUnico() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            String token = hasher.newToken();
            assertThat(token).matches(ValidationPatterns.REFRESH_TOKEN);
            tokens.add(token);
        }
        assertThat(tokens).hasSize(1000);
    }

    @Test
    void hash_esSha256HexDeterminista() {
        // Valor de referencia: printf 'abc' | sha256sum
        assertThat(hasher.hash("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertThat(hasher.hash("abc")).isEqualTo(hasher.hash("abc"));
    }
}
