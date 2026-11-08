package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RegisterRequestTest {

    private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    private static Set<String> invalidFields(Object request) {
        Set<ConstraintViolation<Object>> violations = VALIDATOR.validate(request);
        return violations.stream().map(v -> v.getPropertyPath().toString()).collect(Collectors.toSet());
    }

    @Test
    void constructor_normalizaUsuarioCorreoYNombre() {
        RegisterRequest r = new RegisterRequest("  Ana.Lopez ", " ANA@Ejemplo.COM ", "  Ana  ", " clave ");
        assertThat(r.username()).isEqualTo("ana.lopez");
        assertThat(r.email()).isEqualTo("ana@ejemplo.com");
        assertThat(r.displayName()).isEqualTo("Ana");
        assertThat(r.password()).isEqualTo(" clave ");
    }

    @Test
    void constructor_aceptaNulosSinFallar() {
        RegisterRequest r = new RegisterRequest(null, null, null, null);
        assertThat(invalidFields(r)).containsExactlyInAnyOrder("username", "email", "displayName", "password");
    }

    @Test
    void toString_enmascaraSecretosPeroConservaContexto() {
        // El toString del record por defecto incluiría la contraseña; un toString vacío perdería contexto
        assertThat(new RegisterRequest("ana", "a@b.com", "Ana", "Secreta-123456").toString())
                .isEqualTo("RegisterRequest[username=ana, password=****]");
        assertThat(new LoginRequest("ana", "Secreta-123456").toString())
                .isEqualTo("LoginRequest[username=ana, password=****]");
        assertThat(new RefreshRequest("tok".repeat(15)).toString()).isEqualTo("RefreshRequest[refreshToken=****]");
        assertThat(new TokenResponse("acc", "Bearer", 1, "ref", 2).toString())
                .isEqualTo("TokenResponse[tokenType=Bearer, expiresIn=1, tokens=****]");
    }

    @ParameterizedTest
    @ValueSource(ints = {11, 129})
    void password_fueraDeLongitud_esInvalida(int length) {
        assertThat(invalidFields(new RegisterRequest("ana", "a@b.com", "Ana", "x".repeat(length))))
                .containsExactly("password");
    }

    @ParameterizedTest
    @ValueSource(ints = {12, 128})
    void password_enLimites_esValida(int length) {
        assertThat(invalidFields(new RegisterRequest("ana", "a@b.com", "Ana", "x".repeat(length)))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ana lopez", "ana@lopez", "añá"})
    void username_fueraDeAllowlist_esInvalido(String username) {
        assertThat(invalidFields(new RegisterRequest(username, "a@b.com", "Ana", "x".repeat(12))))
                .containsExactly("username");
    }

    @Test
    void displayName_de61Caracteres_esInvalido() {
        assertThat(invalidFields(new RegisterRequest("ana", "a@b.com", "a".repeat(61), "x".repeat(12))))
                .containsExactly("displayName");
    }
}
