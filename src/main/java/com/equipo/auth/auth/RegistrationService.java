package com.equipo.auth.auth;

import com.equipo.auth.common.LogSanitizer;
import com.equipo.auth.user.User;
import com.equipo.auth.user.UserRepository;
import com.equipo.auth.user.UserResponse;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Alta de usuarios. */
@Service
public class RegistrationService {

    private static final Logger LOG = LoggerFactory.getLogger(RegistrationService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final Clock clock;

    public RegistrationService(UserRepository users, PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
            Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.clock = clock;
    }

    /**
     * Registra un usuario con rol USER (el rol nunca viene del cliente).
     *
     * <p>{@code createdAt} se trunca a milisegundos: la base de datos no guarda nanosegundos y, sin
     * truncar, la respuesta del registro y la de {@code /api/users/me} mostrarían instantes distintos.
     *
     * @param request datos validados por el esquema
     * @return perfil creado
     * @throws WeakPasswordException         si la contraseña no cumple la política
     * @throws RegistrationConflictException si el usuario o el correo ya existen
     */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        passwordPolicy.validate(request.password(), request.username());
        if (users.existsByUsernameOrEmail(request.username(), request.email())) {
            throw new RegistrationConflictException();
        }
        User user = new User(request.username(), request.email(), request.displayName(),
                passwordEncoder.encode(request.password()), clock.instant().truncatedTo(ChronoUnit.MILLIS));
        try {
            users.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Dos registros simultáneos con el mismo usuario o correo: gana la restricción UNIQUE
            throw new RegistrationConflictException();
        }
        LOG.info("SECURITY user_registered user={}", LogSanitizer.safe(user.getUsername()));
        return UserResponse.from(user);
    }
}
