# Prompt 01 — Módulo de autenticación (registro y login)

```text
## ROL
Eres un desarrollador backend senior especializado en AppSec. Sigue @CLAUDE.md.

## CONTEXTO
@CLAUDE.md @pom.xml. Proyecto vacío con Spring Boot 4.1.1. Necesito el núcleo del módulo de
autenticación: entidad User, registro (POST /api/auth/register) y login (POST /api/auth/login).

## RESTRICCIONES DE SEGURIDAD
- DTOs record con Bean Validation y allowlists:
  username ^[a-zA-Z0-9._-]{3,30}$, displayName solo letras/espacios/.'- (1-60),
  email con @Email y máx. 254, password 12-128.
- Argon2id (m=19456 KiB, t=2, p=1). Nunca devolver ni registrar la contraseña.
- Registro duplicado: 409 genérico ("No fue posible completar el registro"), sin decir si el
  duplicado es el usuario o el correo.
- Login fallido: siempre 401 "Credenciales inválidas"; si el usuario no existe, verificar
  contra un hash ficticio para igualar el tiempo de respuesta.
- Bloqueo de cuenta tras 5 fallos durante 15 minutos (mismo 401 genérico).

## CRITERIOS DE ACEPTACIÓN
- Registro válido -> 201 con id, username, displayName (sin hash).
- Usuario con "' OR '1'='1" -> 400 (rechazado por el schema, nunca llega a la BD).
- displayName "<script>alert(1)</script>" -> 400.
- 6.º intento fallido con la contraseña correcta -> 401 (cuenta bloqueada).

## FORMATO DE SALIDA
Archivos completos + tests (unitarios con Mockito y Clock fijo) + checklist + riesgos.
```
