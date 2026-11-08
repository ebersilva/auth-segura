package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.equipo.auth.user.Role;
import com.equipo.auth.user.User;
import com.equipo.auth.user.UserRepository;
import com.equipo.auth.user.UserResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

class RegistrationServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final RegistrationService service = new RegistrationService(users, encoder, new PasswordPolicy(),
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final RegisterRequest request = new RegisterRequest("ana", "ana@ejemplo.com", "Ana",
            "Correcta-Caballo-42");

    @Test
    void register_datosValidos_guardaHashYRolUser() {
        // Arrange
        when(encoder.encode("Correcta-Caballo-42")).thenReturn("$argon2id$hash");

        // Act
        UserResponse response = service.register(request);

        // Assert
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(users).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("$argon2id$hash");
        assertThat(response.role()).isEqualTo(Role.USER);
        assertThat(response.createdAt()).isEqualTo(NOW);
    }

    @Test
    void register_duplicado_lanzaConflictoSinHashear() {
        when(users.existsByUsernameOrEmail("ana", "ana@ejemplo.com")).thenReturn(true);
        assertThatThrownBy(() -> service.register(request)).isInstanceOf(RegistrationConflictException.class);
        verify(encoder, never()).encode(any());
    }

    @Test
    void register_carreraConRestriccionUnique_lanzaConflicto() {
        when(users.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("dup"));
        assertThatThrownBy(() -> service.register(request)).isInstanceOf(RegistrationConflictException.class);
    }

    @Test
    void register_contrasenaDebil_lanzaAntesDeConsultar() {
        RegisterRequest weak = new RegisterRequest("ana", "ana@ejemplo.com", "Ana", "password1234");
        assertThatThrownBy(() -> service.register(weak)).isInstanceOf(WeakPasswordException.class);
        verify(users, never()).existsByUsernameOrEmail(any(), any());
    }
}
