package com.equipo.auth.user;

import java.time.Instant;
import java.util.UUID;

/**
 * Representación pública de un usuario (sin hash ni datos de bloqueo).
 *
 * @param id          identificador
 * @param username    nombre de usuario
 * @param email       correo
 * @param displayName nombre visible
 * @param role        rol
 * @param createdAt   fecha de alta
 */
public record UserResponse(UUID id, String username, String email, String displayName, Role role,
        Instant createdAt) {

    /** Construye la respuesta a partir de la entidad. */
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail(), user.getDisplayName(),
                user.getRole(), user.getCreatedAt());
    }
}
