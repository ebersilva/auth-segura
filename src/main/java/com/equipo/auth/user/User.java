package com.equipo.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** Usuario registrado. Solo guarda el hash Argon2id de la contraseña, nunca la contraseña. */
@Entity
@Table(name = "users")
public class User {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 30)
    private String username;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(nullable = false, length = 60)
    private String displayName;

    @Column(nullable = false, length = 200)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Column(nullable = false)
    private int failedLoginAttempts;

    private Instant lockedUntil;

    @Column(nullable = false)
    private Instant createdAt;

    protected User() {
        // requerido por JPA
    }

    /**
     * Crea un usuario con rol {@link Role#USER}.
     *
     * @param username     nombre de usuario normalizado
     * @param email        correo normalizado
     * @param displayName  nombre visible
     * @param passwordHash hash Argon2id de la contraseña
     * @param createdAt    instante de creación
     */
    public User(String username, String email, String displayName, String passwordHash, Instant createdAt) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.email = email;
        this.displayName = displayName;
        this.passwordHash = passwordHash;
        this.role = Role.USER;
        this.createdAt = createdAt;
    }

    /**
     * Indica si la cuenta está bloqueada.
     *
     * @param now instante actual
     * @return {@code true} si hay un bloqueo vigente
     */
    public boolean isLocked(Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }

    /**
     * Registra un intento fallido y bloquea la cuenta al llegar al máximo.
     *
     * @param now          instante actual
     * @param maxAttempts  intentos permitidos antes del bloqueo
     * @param lockDuration duración del bloqueo
     * @return {@code true} si este intento provocó el bloqueo
     */
    public boolean registerFailedLogin(Instant now, int maxAttempts, Duration lockDuration) {
        failedLoginAttempts++;
        if (failedLoginAttempts >= maxAttempts) {
            lockedUntil = now.plus(lockDuration);
            failedLoginAttempts = 0;
            return true;
        }
        return false;
    }

    /** Reinicia el contador tras un login exitoso. */
    public void resetFailedLogins() {
        failedLoginAttempts = 0;
        lockedUntil = null;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Role getRole() {
        return role;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
