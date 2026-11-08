package com.equipo.auth.auth;

import com.equipo.auth.user.UserResponse;
import jakarta.validation.Valid;
import java.net.URI;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints de autenticación. Register, login y refresh son públicos; logout requiere access token. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService service;
    private final RegistrationService registration;

    public AuthController(AuthService service, RegistrationService registration) {
        this.service = service;
        this.registration = registration;
    }

    /** Registra un usuario: 201 con el perfil. */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse user = registration.register(request);
        return ResponseEntity.created(URI.create("/api/users/me")).body(user);
    }

    /** Inicia sesión: 200 con el par de tokens (sin caché). */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.login(request));
    }

    /** Renueva los tokens con rotación del refresh token. */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.refresh(request));
    }

    /** Cierra la sesión: 204. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody RefreshRequest request) {
        service.logout(jwt, request);
        return ResponseEntity.noContent().build();
    }
}
