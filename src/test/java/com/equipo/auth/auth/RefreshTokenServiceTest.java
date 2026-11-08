package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.equipo.auth.config.JwtProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class RefreshTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");
    private static final UUID USER = UUID.randomUUID();
    private static final UUID FAMILY = UUID.randomUUID();

    private final RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
    private final TokenHasher hasher = new TokenHasher();
    private final JwtProperties props = new JwtProperties("s", "iss", "aud", Duration.ofMinutes(15),
            Duration.ofDays(7));
    private final RefreshTokenService service = new RefreshTokenService(repository, hasher, props,
            Clock.fixed(NOW, ZoneOffset.UTC));

    private RefreshToken stored(String raw, Instant expiresAt) {
        RefreshToken token = new RefreshToken(hasher.hash(raw), USER, FAMILY, NOW.minusSeconds(60), expiresAt);
        when(repository.findByTokenHash(hasher.hash(raw))).thenReturn(Optional.of(token));
        return token;
    }

    @Test
    void issueNewFamily_guardaSoloElHashConExpiracion() {
        // Act
        RefreshTokenService.Issued issued = service.issueNewFamily(USER);

        // Assert
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getTokenHash()).isEqualTo(hasher.hash(issued.token()))
                .isNotEqualTo(issued.token());
        assertThat(captor.getValue().getExpiresAt()).isEqualTo(NOW.plus(Duration.ofDays(7)));
        assertThat(captor.getValue().getUserId()).isEqualTo(USER);
        assertThat(issued.toString()).isEqualTo("Issued[userId=" + USER + ", token=****]");
    }

    @Test
    void rotate_tokenVigente_loRevocaYEmiteOtroDeLaMismaFamilia() {
        // Arrange
        RefreshToken current = stored("actual", NOW.plusSeconds(60));

        // Act
        RefreshTokenService.Issued issued = service.rotate("actual");

        // Assert
        assertThat(current.isRevoked()).isTrue();
        assertThat(current.getRevokedAt()).isEqualTo(NOW);
        assertThat(current.getId()).isNotNull();
        verify(repository).saveAndFlush(current);
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getFamilyId()).isEqualTo(FAMILY);
        assertThat(issued.userId()).isEqualTo(USER);
    }

    @Test
    void rotate_tokenYaUsado_revocaFamiliaYLanza() {
        // Arrange
        stored("robado", NOW.plusSeconds(60)).revoke(NOW.minusSeconds(10));

        // Act + Assert
        assertThatThrownBy(() -> service.rotate("robado")).isInstanceOf(InvalidTokenException.class);
        verify(repository).revokeFamily(FAMILY, NOW);
        verify(repository, never()).save(any());
    }

    @Test
    void rotate_tokenExpirado_lanzaSinEmitir() {
        // Arrange: expira exactamente ahora
        stored("viejo", NOW);

        // Act + Assert
        assertThatThrownBy(() -> service.rotate("viejo")).isInstanceOf(InvalidTokenException.class);
        verify(repository, never()).save(any());
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void rotate_tokenDesconocido_lanza() {
        when(repository.findByTokenHash(any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.rotate("inventado")).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void revokeFamily_delPropioUsuario_revoca() {
        stored("mio", NOW.plusSeconds(60));
        service.revokeFamily("mio", USER);
        verify(repository).revokeFamily(FAMILY, NOW);
    }

    @Test
    void revokeFamily_deOtroUsuario_lanzaSinRevocar() {
        stored("ajeno", NOW.plusSeconds(60));
        assertThatThrownBy(() -> service.revokeFamily("ajeno", UUID.randomUUID()))
                .isInstanceOf(InvalidTokenException.class);
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void ttlSeconds_devuelveVigenciaConfigurada() {
        assertThat(service.ttlSeconds()).isEqualTo(604_800);
    }
}
