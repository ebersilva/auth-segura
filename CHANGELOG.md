# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
[versionado semántico](https://semver.org/lang/es/).

## [0.1.1] - 2026-11-07

### Corregido
- CI: el job de Trivy fallaba en GitHub Actions con `429 Too Many Requests` de Maven Central antes de escanear.
  Ahora llena `~/.m2` con `dependency:go-offline` y Trivy escanea con `--offline-scan` (hallazgo H10).

## [0.1.0] - 2026-11-07

### Añadido
- Configuración de IA con reglas de seguridad: `CLAUDE.md`, `.cursorrules`,
  `.github/copilot-instructions.md` y prompts estructurados en `docs/prompts/`.
- Endpoints `POST /api/auth/register`, `/login`, `/refresh`, `/logout` y `GET /api/users/me`.
- Validación con esquemas (Bean Validation y allowlists), rechazo de propiedades desconocidas y
  límite de 4 KB por cuerpo.
- Hash de contraseñas Argon2id (19 MiB, t=2, p=1) y política de contraseñas (12–128, comunes, usuario).
- JWT HS256 de 15 minutos con validación de `iss`, `aud`, `sub`, `jti`, `iat`, `nbf` y `exp`
  estricto; secreto obligatorio por variable de entorno (fail fast).
- Refresh tokens opacos hasheados, de un solo uso, con rotación, detección de reutilización
  (revoca la familia) y bloqueo optimista ante usos simultáneos.
- Logout con revocación del access token por `jti`.
- Rate limiting con token bucket (por IP y por usuario), 429 con `Retry-After` y bloqueo de cuenta.
- Cabeceras de seguridad, CORS restringido, errores RFC 9457 y eventos `SECURITY` en los logs.
- 170 pruebas (unitarias, de seguridad y de integración); JaCoCo ≥ 90 %, PIT, Checkstyle y
  SpotBugs + Find Security Bugs en el build.
- Pipeline CI con cinco gates (build, CodeQL, Dependency Review, Trivy, Gitleaks), agregador
  `security-gate` y Dependabot.

### Cambiado
- Spring Boot 4.1.1 → **4.1.2**: Trivy detectó 9 CVE (4 críticos en Tomcat 11.0.24 y 5 altos
  en Jackson 3.1.5). La versión 4.1.2 trae Tomcat 11.0.27 y Jackson 3.1.7.
- `AuthService` se dividió en `RegistrationService` y `LoginAttemptGuard` (una sola responsabilidad
  por clase; Checkstyle `ParameterNumber`).
- Las pruebas usan una base H2 propia por contexto de Spring: con la base compartida, el `create-drop` de un
  contexto que se cerraba borraba las tablas de los demás (fallos según el orden de ejecución).
- `RequestSizeFilter` rechaza cualquier `Transfer-Encoding` (411) para cerrar el vector de request
  smuggling TE + CL que reveló un mutante superviviente de PIT.

### Seguridad (corregido)
- El access token se aceptaba en el instante exacto de `exp`. `JwtTimestampValidator` usa
  `isAfter`, y la RFC 7519 exige `now < exp`. Se agregó `AccessTokenValidators.strictExpiry`.
- 23 hallazgos de SpotBugs/FindSecBugs: inyección CRLF en logs (`LogSanitizer`), posibles NPE con
  claims ausentes (`TokenClaims`), representación mutable en propiedades, constructor que lanza
  excepción en una clase no `final`. Las excepciones justificadas están en `config/spotbugs/exclude.xml`.
- `createdAt` del registro con nanosegundos no coincidía con el valor leído de la base de datos;
  ahora se trunca a milisegundos.
- El límite por usuario en el login no dejaba evento de seguridad; ahora registra
  `SECURITY login_rate_limited`.
