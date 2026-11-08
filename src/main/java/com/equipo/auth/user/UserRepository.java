package com.equipo.auth.user;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Acceso a usuarios. Solo consultas derivadas: Spring Data las parametriza (sin SQL concatenado). */
public interface UserRepository extends JpaRepository<User, UUID> {

    /** Busca por nombre de usuario normalizado. */
    Optional<User> findByUsername(String username);

    /** Indica si ya existe el nombre de usuario o el correo. */
    boolean existsByUsernameOrEmail(String username, String email);
}
