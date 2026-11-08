# CLAUDE.md — auth-segura

Contexto y reglas para Claude Code. Este archivo es el contrato que la IA debe cumplir en
cada generación. Las mismas reglas están en `.cursorrules` (Cursor) y en
`.github/copilot-instructions.md` (GitHub Copilot); si cambias una, cambia las tres.

## Proyecto

API REST de autenticación de usuarios: registro, login, renovación de tokens, logout y
consulta del perfil autenticado.

- Java 25, Spring Boot 4.1.1, Spring Security 7.1, Maven Wrapper (`./mvnw`).
- Persistencia: Spring Data JPA + H2 en memoria (desarrollo). En producción, PostgreSQL.
- JWT: `spring-boot-starter-security-oauth2-resource-server` (Nimbus). Sin librerías JWT de terceros.
- Hash de contraseñas: Argon2id (`Argon2PasswordEncoder` + BouncyCastle).

## Estructura de paquetes (`com.equipo.auth`)

| Paquete | Responsabilidad |
|---|---|
| `auth` | Casos de uso de autenticación, DTOs, refresh tokens, emisión de JWT |
| `user` | Entidad `User`, repositorio, endpoint `/api/users/me` |
| `ratelimit` | Token bucket, filtro por IP, políticas |
| `security` | Validadores y manejadores de seguridad (lista de revocación, entry point) |
| `config` | `SecurityFilterChain`, propiedades tipadas, beans de infraestructura |
| `common.error` | `GlobalExceptionHandler` y formato RFC 9457 |

## Reglas de seguridad (obligatorias, no negociables)

1. **Secretos**: nunca en el código, en tests de producción ni en `application.properties`
   versionado. Se leen de variables de entorno (`JWT_SECRET`). La app **falla al arrancar**
   si el secreto falta o tiene menos de 256 bits.
2. **Entrada no confiable**: todo DTO es un `record` con Bean Validation (`@NotNull`, `@Size`,
   `@Pattern`). Listas de caracteres permitidos (allowlist), nunca listas negras. JSON con
   propiedades desconocidas se rechaza. Cuerpo máximo: 4 KB.
3. **SQL**: solo consultas derivadas de Spring Data o JPQL con parámetros. Prohibido concatenar
   strings en consultas, `nativeQuery` con concatenación o `createQuery("..." + x)`.
4. **Contraseñas**: Argon2id con parámetros OWASP (m = 19 MiB, t = 2, p = 1). Nunca registrar,
   devolver ni comparar contraseñas en claro. Longitud 12–128.
5. **Errores**: `application/problem+json` sin stack traces, sin nombres de clases y sin
   mensajes que revelen si un usuario existe. El login fallido siempre responde lo mismo y
   tarda lo mismo (hash ficticio si el usuario no existe).
6. **JWT**: access token de 15 minutos, HS256, con `iss`, `aud`, `sub`, `exp`, `iat` y `jti`
   validados. Refresh token opaco (256 bits aleatorios), guardado **hasheado**, de un solo uso,
   rotado en cada renovación; si se reutiliza, se revoca toda la familia.
7. **Rate limiting**: todo endpoint de `/api/auth/**` pasa por el limitador por IP; el login
   además limita por usuario y bloquea la cuenta tras 5 fallos. Responde 429 con `Retry-After`.
8. **Logs**: nunca registrar contraseñas, tokens, cabeceras `Authorization` ni el cuerpo de
   las peticiones de autenticación. Sí registrar eventos de seguridad (login fallido,
   reutilización de refresh, bloqueo) con el `username` saneado.
9. **Dependencias**: no agregar dependencias sin justificarlo; el pipeline las escanea con
   Trivy y Dependency Review y falla ante vulnerabilidades HIGH/CRITICAL.
10. **Tiempo**: inyectar `java.time.Clock`; nunca `Instant.now()` directo (hace los tests de
    expiración deterministas).

## Convenciones de código

- 4 espacios, líneas ≤ 120, inyección por constructor, DTOs como `record`.
- Javadoc en todo tipo público (Checkstyle lo exige).
- Excepciones de dominio propias; el `GlobalExceptionHandler` las traduce a HTTP.

## Convenciones de tests

- JUnit 5 + AssertJ + Mockito, estructura Arrange–Act–Assert marcada con comentarios.
- Nombres `metodo_condicion_resultado`.
- Cada regla de seguridad tiene al menos un test que intenta romperla (`security/*SecurityTest`).
- Cobertura mínima de líneas y ramas: 90 % (JaCoCo hace fallar el build).

## Comandos

```bash
export JWT_SECRET=$(openssl rand -base64 48)
./mvnw verify                 # Checkstyle + tests + JaCoCo + SpotBugs/FindSecBugs
./mvnw spring-boot:run        # API en http://localhost:8081
```

## Checklist antes de dar una tarea por terminada

- [ ] `./mvnw verify` en verde (0 violaciones, 0 hallazgos de SpotBugs, cobertura ≥ 90 %).
- [ ] Hay un test negativo (ataque) por cada regla nueva.
- [ ] No hay secretos, contraseñas ni tokens en código, logs o respuestas.
- [ ] README, CHANGELOG y `docs/evidencia/proceso.md` actualizados.
