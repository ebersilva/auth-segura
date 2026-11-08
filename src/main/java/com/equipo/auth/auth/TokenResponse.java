package com.equipo.auth.auth;

/**
 * Par de tokens emitido en login y refresh.
 *
 * @param accessToken      JWT de acceso
 * @param tokenType        siempre {@code Bearer}
 * @param expiresIn        segundos de vigencia del access token
 * @param refreshToken     refresh token opaco de un solo uso
 * @param refreshExpiresIn segundos de vigencia del refresh token
 */
public record TokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken,
        long refreshExpiresIn) {

    @Override
    public String toString() {
        return "TokenResponse[tokenType=" + tokenType + ", expiresIn=" + expiresIn + ", tokens=****]";
    }
}
