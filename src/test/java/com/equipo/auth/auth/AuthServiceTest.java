package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.equipo.auth.ratelimit.RateLimitExceededException;
import com.equipo.auth.security.AccessTokenDenylist;
import com.equipo.auth.user.User;
import com.equipo.auth.user.UserRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");
    private static final String REFRESH = "r".repeat(43);

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final AccessTokenService accessTokens = mock(AccessTokenService.class);
    private final RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
    private final AccessTokenDenylist denylist = mock(AccessTokenDenylist.class);
    private final LoginAttemptGuard guard = mock(LoginAttemptGuard.class);
    private AuthService service;
    private User user;

    @BeforeEach
    void setUp() {
        service = new AuthService(users, encoder, accessTokens, refreshTokens, denylist, guard,
                Clock.fixed(NOW, ZoneOffset.UTC));
        user = new User("ana", "ana@ejemplo.com", "Ana", "HASH", NOW);
        when(accessTokens.issue(any())).thenReturn("ACCESS");
        when(accessTokens.ttlSeconds()).thenReturn(900L);
        when(refreshTokens.ttlSeconds()).thenReturn(604_800L);
    }

    @Test
    void login_credencialesValidas_emiteTokensYReiniciaContador() {
        // Arrange
        user.registerFailedLogin(NOW, 5, Duration.ofMinutes(15));
        when(users.findByUsername("ana")).thenReturn(Optional.of(user));
        when(encoder.matches("secreta", "HASH")).thenReturn(true);
        when(refreshTokens.issueNewFamily(user.getId())).thenReturn(new RefreshTokenService.Issued(user.getId(),
                REFRESH));

        // Act
        TokenResponse response = service.login(new LoginRequest("ana", "secreta"));

        // Assert
        assertThat(response).isEqualTo(new TokenResponse("ACCESS", "Bearer", 900, REFRESH, 604_800));
        assertThat(user.getFailedLoginAttempts()).isZero();
        verify(guard).checkRateLimit("ana");
        verify(users).save(user);
    }

    @Test
    void login_usuarioInexistente_gastaTiempoEquivalenteYLanzaGenerico() {
        // Arrange
        when(users.findByUsername("nadie")).thenReturn(Optional.empty());

        // Act + Assert
        assertThatThrownBy(() -> service.login(new LoginRequest("nadie", "x")))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Credenciales inválidas");
        verify(guard).spendEquivalentTime("x");
        verify(refreshTokens, never()).issueNewFamily(any());
    }

    @Test
    void login_cuentaBloqueada_noVerificaContrasenaRealYLanzaGenerico() {
        // Arrange
        user.registerFailedLogin(NOW, 1, Duration.ofMinutes(15));
        when(users.findByUsername("ana")).thenReturn(Optional.of(user));

        // Act + Assert
        assertThatThrownBy(() -> service.login(new LoginRequest("ana", "secreta")))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(guard).spendEquivalentTime("secreta");
        verify(encoder, never()).matches("secreta", "HASH");
    }

    @Test
    void login_contrasenaIncorrecta_registraFalloYGuarda() {
        // Arrange
        when(users.findByUsername("ana")).thenReturn(Optional.of(user));
        when(encoder.matches("mala", "HASH")).thenReturn(false);

        // Act + Assert
        assertThatThrownBy(() -> service.login(new LoginRequest("ana", "mala")))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(guard).registerFailure(user, NOW);
        verify(users).save(user);
    }

    @Test
    void login_limiteExcedido_noConsultaLaBaseDeDatos() {
        // Arrange
        doThrow(new RateLimitExceededException(20)).when(guard).checkRateLimit("ana");

        // Act + Assert
        assertThatThrownBy(() -> service.login(new LoginRequest("ana", "x")))
                .isInstanceOf(RateLimitExceededException.class);
        verify(users, never()).findByUsername(any());
    }

    @Test
    void refresh_tokenValido_emiteNuevoPar() {
        // Arrange
        when(refreshTokens.rotate(REFRESH)).thenReturn(new RefreshTokenService.Issued(user.getId(), "NUEVO"));
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        // Act
        TokenResponse response = service.refresh(new RefreshRequest(REFRESH));

        // Assert
        assertThat(response.refreshToken()).isEqualTo("NUEVO");
        assertThat(response.accessToken()).isEqualTo("ACCESS");
    }

    @Test
    void refresh_usuarioEliminado_lanzaTokenInvalido() {
        // Arrange
        UUID ghost = UUID.randomUUID();
        when(refreshTokens.rotate(REFRESH)).thenReturn(new RefreshTokenService.Issued(ghost, "NUEVO"));
        when(users.findById(ghost)).thenReturn(Optional.empty());

        // Act + Assert
        assertThatThrownBy(() -> service.refresh(new RefreshRequest(REFRESH)))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void logout_revocaFamiliaYAccessToken() {
        // Arrange
        Instant exp = NOW.plusSeconds(900);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "HS256").subject(user.getId().toString()).jti("jti-1")
                .expiresAt(exp).claim("username", "ana").build();

        // Act
        service.logout(jwt, new RefreshRequest(REFRESH));

        // Assert
        verify(refreshTokens).revokeFamily(REFRESH, user.getId());
        verify(denylist).revoke("jti-1", exp);
    }

    @Test
    void logout_tokenSinExpONiJti_lanzaSinRevocar() {
        // Arrange: no debería ocurrir con el decoder configurado, pero el servicio no confía en ello
        Jwt sinJti = Jwt.withTokenValue("t").header("alg", "HS256").subject(user.getId().toString())
                .expiresAt(NOW.plusSeconds(900)).build();
        Jwt sinExp = Jwt.withTokenValue("t").header("alg", "HS256").subject(user.getId().toString())
                .jti("j").build();

        // Act + Assert
        assertThatThrownBy(() -> service.logout(sinJti, new RefreshRequest(REFRESH)))
                .isInstanceOf(InvalidTokenException.class);
        assertThatThrownBy(() -> service.logout(sinExp, new RefreshRequest(REFRESH)))
                .isInstanceOf(InvalidTokenException.class);
        verify(refreshTokens, never()).revokeFamily(any(), any());
    }
}
