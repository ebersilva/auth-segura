package com.equipo.auth.auth;

import com.equipo.auth.common.LogSanitizer;
import com.equipo.auth.ratelimit.RateLimitExceededException;
import com.equipo.auth.security.AccessTokenDenylist;
import com.equipo.auth.user.User;
import com.equipo.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Casos de uso de sesión: login, renovación y logout. */
@Service
public class AuthService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenService accessTokens;
    private final RefreshTokenService refreshTokens;
    private final AccessTokenDenylist denylist;
    private final LoginAttemptGuard guard;
    private final Clock clock;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder, AccessTokenService accessTokens,
            RefreshTokenService refreshTokens, AccessTokenDenylist denylist, LoginAttemptGuard guard, Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
        this.denylist = denylist;
        this.guard = guard;
        this.clock = clock;
    }

    /**
     * Autentica y emite un par de tokens.
     *
     * <p>Usuario inexistente, contraseña incorrecta y cuenta bloqueada producen la misma excepción y
     * ejecutan una verificación Argon2 completa, para que ni el mensaje ni el tiempo revelen la causa.
     * {@code noRollbackFor}: el contador de fallos debe persistir aunque se lance la excepción.
     *
     * @param request credenciales
     * @return access y refresh token
     * @throws RateLimitExceededException  si el usuario superó los intentos del periodo
     * @throws InvalidCredentialsException si las credenciales no son válidas o la cuenta está bloqueada
     */
    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public TokenResponse login(LoginRequest request) {
        guard.checkRateLimit(request.username());
        Instant now = clock.instant();
        User user = users.findByUsername(request.username()).orElse(null);
        if (user == null || user.isLocked(now)) {
            guard.spendEquivalentTime(request.password());
            LOG.warn("SECURITY login_failed user={} reason={}", LogSanitizer.safe(request.username()),
                    user == null ? "unknown_user" : "locked");
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            boolean lockedNow = guard.registerFailure(user, now);
            users.save(user);
            LOG.warn("SECURITY login_failed user={} reason=bad_password locked={}",
                    LogSanitizer.safe(user.getUsername()), lockedNow);
            throw new InvalidCredentialsException();
        }
        user.resetFailedLogins();
        users.save(user);
        LOG.info("SECURITY login_ok user={}", LogSanitizer.safe(user.getUsername()));
        return tokensFor(user, refreshTokens.issueNewFamily(user.getId()).token());
    }

    /**
     * Rota el refresh token y emite un nuevo access token.
     *
     * @param request refresh token actual
     * @return nuevo par de tokens
     * @throws InvalidTokenException si el refresh token no es válido o fue reutilizado
     */
    public TokenResponse refresh(RefreshRequest request) {
        RefreshTokenService.Issued issued = refreshTokens.rotate(request.refreshToken());
        User user = users.findById(issued.userId()).orElseThrow(InvalidTokenException::new);
        return tokensFor(user, issued.token());
    }

    /**
     * Cierra la sesión: revoca la familia del refresh token y el access token actual.
     *
     * @param accessToken access token validado
     * @param request     refresh token de la sesión
     * @throws InvalidTokenException si el refresh token no pertenece al usuario
     */
    public void logout(Jwt accessToken, RefreshRequest request) {
        Instant expiresAt = accessToken.getExpiresAt();
        String jti = accessToken.getId();
        if (expiresAt == null || jti == null) {
            throw new InvalidTokenException();
        }
        refreshTokens.revokeFamily(request.refreshToken(), TokenClaims.userId(accessToken));
        denylist.revoke(jti, expiresAt);
        LOG.info("SECURITY logout user={}", LogSanitizer.safe(accessToken.getClaimAsString("username")));
    }

    private TokenResponse tokensFor(User user, String refreshToken) {
        return new TokenResponse(accessTokens.issue(user), "Bearer", accessTokens.ttlSeconds(), refreshToken,
                refreshTokens.ttlSeconds());
    }
}
