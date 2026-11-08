package com.equipo.auth.user;

import com.equipo.auth.auth.InvalidTokenException;
import com.equipo.auth.auth.TokenClaims;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints del usuario autenticado. Requieren un access token válido. */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository users;

    public UserController(UserRepository users) {
        this.users = users;
    }

    /**
     * Devuelve el perfil del usuario dueño del token.
     *
     * @param jwt token validado por el resource server
     * @return perfil público
     * @throws InvalidTokenException si el usuario del token ya no existe
     */
    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return users.findById(TokenClaims.userId(jwt))
                .map(UserResponse::from)
                .orElseThrow(InvalidTokenException::new);
    }
}
