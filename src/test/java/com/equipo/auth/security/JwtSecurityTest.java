package com.equipo.auth.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.equipo.auth.support.AbstractApiTest;
import com.equipo.auth.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

/** Ataques contra los access tokens: todos deben responder 401 sin revelar la causa. */
class JwtSecurityTest extends AbstractApiTest {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    private JwtEncoder encoder;

    @Autowired
    private UserRepository users;

    private void expectRejected(String token) throws Exception {
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"invalid_token\""))
                .andExpect(jsonPath("$.detail").value("Se requiere un token de acceso válido"));
    }

    /** Firma con la clave real un token con los claims válidos modificados por {@code customizer}. */
    private String signed(String subject, Consumer<JwtClaimsSet.Builder> customizer) {
        Instant now = clock.instant();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer("https://auth-segura.local")
                .audience(List.of("auth-segura-api"))
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(900))
                .id(UUID.randomUUID().toString());
        customizer.accept(claims);
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims.build()))
                .getTokenValue();
    }

    private String subjectOf(String username) {
        return users.findByUsername(username).orElseThrow().getId().toString();
    }

    @Test
    void tokenFirmadoValido_esAceptado() throws Exception {
        // Control positivo: el mismo generador produce tokens válidos, así que los rechazos son por el ataque
        String token = signed(subjectOf(registerUser()), c -> { });
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
    }

    @Test
    void algNone_esRechazado() throws Exception {
        // Arrange: token sin firma con alg=none (CVE-2015-9235 y similares)
        String header = B64.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64.encodeToString(("{\"sub\":\"" + subjectOf(registerUser())
                + "\",\"iss\":\"https://auth-segura.local\",\"aud\":\"auth-segura-api\",\"exp\":4102444800,"
                + "\"iat\":1794052800,\"jti\":\"x\"}").getBytes(StandardCharsets.UTF_8));

        // Act + Assert
        expectRejected(header + "." + payload + ".");
    }

    @Test
    void firmaAlterada_esRechazada() throws Exception {
        String token = read(login(registerUser()), "$.accessToken");
        char last = token.charAt(token.length() - 2);
        String tampered = token.substring(0, token.length() - 2) + (last == 'A' ? 'B' : 'A')
                + token.charAt(token.length() - 1);
        expectRejected(tampered);
    }

    @Test
    void payloadAlterado_suplantandoOtroUsuario_esRechazado() throws Exception {
        // Arrange: el atacante cambia "sub" por el de la víctima y conserva su firma
        String victimId = subjectOf(registerUser());
        String[] parts = read(login(registerUser()), "$.accessToken").split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
                .replaceFirst("\"sub\":\"[^\"]+\"", "\"sub\":\"" + victimId + "\"");

        // Act + Assert
        expectRejected(parts[0] + "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "."
                + parts[2]);
    }

    @Test
    void firmadoConOtraClave_esRechazado() throws Exception {
        // Token HS256 bien formado pero firmado por un atacante con su propia clave
        String header = B64.encodeToString("{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64.encodeToString(("{\"sub\":\"" + subjectOf(registerUser()) + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        expectRejected(header + "." + payload + "." + B64.encodeToString(new byte[32]));
    }

    @Test
    void emisorIncorrecto_esRechazado() throws Exception {
        expectRejected(signed(subjectOf(registerUser()), c -> c.issuer("https://atacante.example")));
    }

    @Test
    void audienciaIncorrecta_esRechazada() throws Exception {
        expectRejected(signed(subjectOf(registerUser()), c -> c.audience(List.of("otra-api"))));
    }

    @Test
    void sinJti_esRechazado() throws Exception {
        expectRejected(signed(subjectOf(registerUser()), c -> c.claims(m -> m.remove("jti"))));
    }

    @Test
    void expirado_esRechazado() throws Exception {
        Instant past = clock.instant().minusSeconds(3600);
        expectRejected(signed(subjectOf(registerUser()), c -> c.issuedAt(past).expiresAt(past.plusSeconds(900))));
    }

    @Test
    void notBeforeFuturo_esRechazado() throws Exception {
        expectRejected(signed(subjectOf(registerUser()), c -> c.notBefore(clock.instant().plusSeconds(600))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"basura", "a.b.c", "eyJhbGciOiJIUzI1NiJ9..", "' OR '1'='1"})
    void tokenMalFormado_esRechazado(String token) throws Exception {
        expectRejected(token);
    }

    @Test
    void sinToken_devuelve401SinDetalleDeError() throws Exception {
        mvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"));
    }
}
