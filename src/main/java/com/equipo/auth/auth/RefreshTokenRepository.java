package com.equipo.auth.auth;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Acceso a refresh tokens. Consultas derivadas o JPQL con parámetros nombrados. */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /** Busca por el hash del valor presentado. */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Tokens de una familia (para auditoría y pruebas). */
    List<RefreshToken> findByFamilyId(UUID familyId);

    /**
     * Revoca todos los tokens vigentes de una familia.
     *
     * @return número de tokens revocados
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update RefreshToken r set r.revokedAt = :now where r.familyId = :familyId and r.revokedAt is null")
    int revokeFamily(@Param("familyId") UUID familyId, @Param("now") Instant now);
}
