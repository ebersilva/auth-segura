package com.equipo.auth.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;

/**
 * Refresh token persistido. Solo se guarda el SHA-256 del valor; el valor en claro únicamente lo
 * recibe el cliente. Todos los tokens rotados a partir del mismo login comparten {@code familyId}.
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_refresh_family", columnList = "familyId"),
    @Index(name = "idx_refresh_user", columnList = "userId")
})
public class RefreshToken {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(nullable = false)
    private UUID userId;

    @Column(nullable = false)
    private UUID familyId;

    @Column(nullable = false)
    private Instant expiresAt;

    private Instant revokedAt;

    @Column(nullable = false)
    private Instant createdAt;

    /** Bloqueo optimista: de dos rotaciones simultáneas del mismo token solo una se confirma. */
    @Version
    private long version;

    protected RefreshToken() {
        // requerido por JPA
    }

    /**
     * Crea un refresh token vigente.
     *
     * @param tokenHash SHA-256 (hex) del valor entregado al cliente
     * @param userId    dueño
     * @param familyId  familia de rotación
     * @param createdAt instante de emisión
     * @param expiresAt instante de expiración
     */
    public RefreshToken(String tokenHash, UUID userId, UUID familyId, Instant createdAt, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.familyId = familyId;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    /** Indica si ya fue usado o revocado. */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /** Indica si expiró en el instante dado. */
    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /** Marca el token como usado/revocado. */
    public void revoke(Instant now) {
        this.revokedAt = now;
    }

    public UUID getId() {
        return id;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getFamilyId() {
        return familyId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}
