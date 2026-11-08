# Instrucciones para GitHub Copilot — auth-segura

> Fuente común: `CLAUDE.md`. Mantener sincronizado con `.cursorrules`.
> Copilot lee este archivo automáticamente en cada sugerencia y en Copilot Chat.

## Contexto del repositorio

API REST de autenticación (registro, login, refresh, logout, perfil) en **Java 25 +
Spring Boot 4.1.1 + Spring Security 7.1**. JWT con Nimbus (resource server), contraseñas con
**Argon2id**, H2 en desarrollo. Paquete raíz `com.equipo.auth`.

## Al sugerir código, siempre

- Valida la entrada con Bean Validation en `record`s: `@NotNull`, `@Size` y `@Pattern` con
  allowlist. Ejemplo de patrón de usuario: `^[a-zA-Z0-9._-]{3,30}$`.
- Usa repositorios Spring Data (consultas derivadas) o JPQL con `:parametros`.
- Lee secretos con `@ConfigurationProperties` desde variables de entorno.
- Usa `SecureRandom` para tokens y `MessageDigest.isEqual` para comparar hashes.
- Inyecta `Clock` para cualquier cálculo de tiempo.
- Devuelve errores como `ProblemDetail` (RFC 9457) con mensajes genéricos.
- Agrega un test de ataque por cada validación: inyección SQL, XSS, token manipulado,
  fuerza bruta (429), reutilización de refresh token.

## Nunca sugieras

- Secretos, contraseñas o JWT de ejemplo en `src/main` o en `application.properties`.
- Concatenación de strings en SQL/JPQL o `nativeQuery` con entrada del usuario.
- `permitAll()` fuera de `/api/auth/**`, CORS con `*`, ni desactivar cabeceras de seguridad.
- Registrar (`log.info`) contraseñas, tokens o la cabecera `Authorization`.
- Mensajes que revelen si un usuario o correo existe ("usuario no encontrado").
- Librerías JWT alternativas (jjwt, java-jwt) ni algoritmos `none`/`RS256` con claves embebidas.
- `MD5`, `SHA-1` o `BCrypt` con costo < 12 para contraseñas.

## Pruebas

- JUnit 5 + AssertJ + Mockito; MockMvc con `spring-security-test` para la capa web.
- Estructura Arrange–Act–Assert con comentarios; nombres `metodo_condicion_resultado`.
- Cobertura mínima 90 % de líneas y ramas (JaCoCo hace fallar el build).

## Revisión de PR (Copilot code review)

Al revisar un pull request, marca como bloqueante: secretos en el diff, validación ausente en
un DTO nuevo, endpoint nuevo sin regla en `SecurityConfig`, consultas concatenadas, logs con
datos sensibles y cualquier test de seguridad eliminado o deshabilitado.
