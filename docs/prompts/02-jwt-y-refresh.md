# Prompt 02 — JWT de acceso y refresh tokens con rotación

```text
## ROL
Eres un desarrollador backend senior especializado en AppSec. Sigue @CLAUDE.md.

## CONTEXTO
@CLAUDE.md @src/main/java/com/equipo/auth/auth/AuthService.java
El login ya valida credenciales. Falta emitir tokens y proteger /api/users/me.

## RESTRICCIONES DE SEGURIDAD
- Access token JWT HS256 de 15 min con iss, aud, sub, exp, iat, jti, firmado con
  NimbusJwtEncoder. Secreto desde JWT_SECRET (Base64, >= 32 bytes); si falta o es corto,
  la aplicación NO arranca.
- Decoder: solo HS256; validar firma, exp/nbf con el Clock inyectado (sin tolerancia extra),
  issuer, audience y que el jti no esté revocado.
- Refresh token: 32 bytes de SecureRandom en Base64URL; en la BD solo su SHA-256.
  Un solo uso: cada /refresh lo revoca y emite otro de la misma familia.
  Si llega un refresh ya usado -> revocar TODA la familia (robo probable) y 401.
- Logout: revoca la familia del refresh y agrega el jti del access token a una lista de
  revocación hasta su expiración.
- Concurrencia: dos /refresh simultáneos con el mismo token -> solo uno gana (@Version).

## CRITERIOS DE ACEPTACIÓN
- Token con alg=none, firma alterada, expirado, otro issuer u otra audiencia -> 401.
- Refresh reutilizado -> 401 y el refresh nuevo de esa familia también deja de servir.
- Tras logout, el access token anterior -> 401.

## FORMATO DE SALIDA
Archivos completos + tests de cada rechazo + checklist + riesgos residuales.
```
