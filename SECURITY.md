# Seguridad — auth-segura

## Reporte de vulnerabilidades

Reporta cualquier vulnerabilidad de forma privada en **GitHub → Security → Report a vulnerability**
(no abras un issue público). Respuesta inicial en 72 horas hábiles.

## Modelo de amenazas (STRIDE) y mitigaciones

Activos: credenciales, hashes de contraseña, access y refresh tokens, el secreto `JWT_SECRET`
y la disponibilidad del servicio de login.

| # | Amenaza | STRIDE | OWASP Top 10 2021 | Mitigación | Prueba que lo demuestra |
|---|---|---|---|---|---|
| T1 | Inyección SQL en usuario, correo o contraseña | Tampering | A03 | Allowlists en el esquema; solo consultas derivadas o JPQL con parámetros; la contraseña nunca llega a SQL | `InjectionAndXssSecurityTest.sqlInjection_*` |
| T2 | XSS almacenado o reflejado (`displayName`, URI en errores) | Tampering | A03 | Allowlist de `displayName`; respuestas JSON con `nosniff` y CSP `default-src 'none'`; `ProblemJson` escapa `< > &` | `xss_*` |
| T3 | Mass assignment (`"role":"ADMIN"`) | Elevation | A01/A08 | `FAIL_ON_UNKNOWN_PROPERTIES`; el rol nunca viene del cliente | `massAssignment_rolAdmin_esRechazado` |
| T4 | Fuerza bruta y credential stuffing | Spoofing | A07 | Token bucket por IP (20/min) y por usuario (5/min); bloqueo de 15 min tras 5 fallos | `BruteForceSecurityTest` |
| T5 | Enumeración de usuarios | Info. disclosure | A07 | Mismo mensaje y mismo costo Argon2 (hash ficticio) si el usuario no existe o está bloqueado | `usuarioInexistente_mismaRespuestaQueContrasenaIncorrecta` |
| T6 | Robo de base de datos → contraseñas | Info. disclosure | A02 | Argon2id con 19 MiB por intento; refresh tokens guardados como SHA-256 | `PasswordConfigTest`, `refreshToken_seGuardaSoloHasheado` |
| T7 | JWT falsificado (`alg=none`, firma o payload alterados, otra clave) | Spoofing | A08 | Decoder exclusivo HS256 con clave ≥ 256 bits | `JwtSecurityTest` |
| T8 | Reuso de tokens expirados o de otro emisor o audiencia | Spoofing | A07 | Validadores de `exp` estricto, `nbf`, `iss`, `aud`, `sub`, `jti` e `iat` | `expirado_*`, `emisorIncorrecto_*`, `audienciaIncorrecta_*` |
| T9 | Robo de refresh token | Spoofing | A07 | Un solo uso con rotación; si se reutiliza, se revoca la familia completa y se registra el evento | `RefreshTokenReuseSecurityTest` |
| T10 | Carrera con el mismo refresh token | Tampering | A04 | `@Version` (bloqueo optimista): solo una renovación gana | `RefreshConcurrencyIntegrationTest` |
| T11 | Sesión que sigue viva tras el logout | Spoofing | A07 | Lista de revocación por `jti` hasta `exp` | `flujoCompleto_*` (paso 5) |
| T12 | DoS por cuerpos grandes, chunked o request smuggling | DoS | A04 | 413 sobre 4 KB; 411 ante cualquier `Transfer-Encoding` | `cuerpoMayorA4Kb_devuelve413`, `FiltersAndEntryPointTest` |
| T13 | Evasión del límite con `X-Forwarded-For` falso | Spoofing | A04 | La IP es `getRemoteAddr()`; los encabezados de proxy solo se usan con `forward-headers-strategy` | `limitePorIp_noSeEvadeConXForwardedFor` |
| T14 | Secreto débil o versionado | Info. disclosure | A02/A05 | `JWT_SECRET` obligatorio de ≥ 256 bits (fail fast); Gitleaks en CI | `StartupWithoutSecretTest`, gate Gitleaks |
| T15 | Fuga de información en errores o logs | Info. disclosure | A05/A09 | RFC 9457 genérico, sin stack traces; logs sin contraseñas ni tokens; CRLF neutralizado | `handleUnexpected_*`, `LogSanitizerTest` |
| T16 | Clickjacking, sniffing de MIME, CORS abierto | Tampering | A05 | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, CORS con lista de orígenes | `respuestas_incluyenCabecerasDeSeguridad`, `cors_*` |
| T17 | Dependencias vulnerables | Tampering | A06 | Trivy, Dependency Review y Dependabot; el gate falla con HIGH/CRITICAL | `docs/evidencia/logs/02-…` y `04-…` |
| T18 | Ataques sin rastro | Repudiation | A09 | Eventos `SECURITY` (login fallido, bloqueo, límite, reutilización de refresh, logout) | `docs/evidencia/logs/08-app-real-eventos-seguridad.log` |

## Decisiones conscientes (riesgo aceptado)

| Decisión | Justificación | Condición para revisarla |
|---|---|---|
| CSRF deshabilitado | API stateless con bearer token en `Authorization`; no hay cookies que el navegador envíe solo | Si algún día el token viaja en cookie, activar CSRF y `SameSite=Strict` |
| HS256 (clave simétrica) | Un solo servicio emite y valida | Con varios servicios validadores, pasar a RS256/EdDSA con JWKS |
| Rate limiter y lista de revocación en memoria | Una sola instancia | Con varias réplicas, moverlos a Redis con TTL |
| 409 en registro duplicado | Permite saber que *algo* ya existe, pero no qué campo; mitigado por el rate limit | Flujo de verificación por correo (siempre 202) |
| H2 en memoria | Entorno de desarrollo del reto | Producción: PostgreSQL con TLS y credenciales por entorno |

## Checklist de producción

- [ ] TLS terminado en el balanceador y `server.forward-headers-strategy=native` para resolver la IP real.
- [ ] `JWT_SECRET` en un gestor de secretos (Vault o GitHub Environments), con rotación planificada.
- [ ] Rate limiter y lista de revocación en Redis.
- [ ] Lista completa de contraseñas comprometidas (API k-anonymity de Have I Been Pwned).
- [ ] Eventos `SECURITY` enviados al SIEM con alertas por `refresh_token_reuse` y picos de `login_failed`.
- [ ] Protección de la rama `main` con `Security gate` como check obligatorio.
