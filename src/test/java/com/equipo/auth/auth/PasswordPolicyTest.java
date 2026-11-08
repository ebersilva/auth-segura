package com.equipo.auth.auth;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @ParameterizedTest
    @ValueSource(strings = {"password1234", "PASSWORD1234", "123456789012", "Contraseña123"})
    void validate_contrasenaComun_lanzaSinImportarMayusculas(String password) {
        assertThatThrownBy(() -> policy.validate(password, "ana"))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessage("es demasiado común");
    }

    @Test
    void validate_contieneUsuario_lanza() {
        assertThatThrownBy(() -> policy.validate("Mi-ANALISTA-2026", "analista"))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessage("no debe contener el nombre de usuario");
    }

    @Test
    void validate_fraseLarga_esValida() {
        assertThatCode(() -> policy.validate("correcta caballo batería grapa", "ana")).doesNotThrowAnyException();
    }
}
