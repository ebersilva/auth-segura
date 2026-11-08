# Prompt 03 — Rate limiting

```text
## ROL
Eres un desarrollador backend senior especializado en AppSec. Sigue @CLAUDE.md.

## CONTEXTO
@CLAUDE.md @src/main/java/com/equipo/auth/config/SecurityConfig.java
Necesito limitar la fuerza bruta y el abuso de /api/auth/**, sin dependencias nuevas.

## RESTRICCIONES DE SEGURIDAD
- Token bucket propio, thread-safe, con Clock inyectado (tests deterministas).
- Por IP en todo /api/auth/** (filtro antes de la autenticación) y por usuario en el login.
- 429 application/problem+json con cabecera Retry-After en segundos (redondeo hacia arriba).
- La IP es request.getRemoteAddr(): NO confiar en X-Forwarded-For (falsificable) salvo
  detrás de un proxy configurado explícitamente.
- Memoria acotada: desalojar buckets inactivos.

## CRITERIOS DE ACEPTACIÓN
- Capacidad N: N peticiones pasan, la N+1 -> 429 con Retry-After > 0.
- Tras el periodo de recarga, vuelve a pasar.
- Cambiar X-Forwarded-For no evade el límite.

## FORMATO DE SALIDA
Archivos completos + tests unitarios con reloj controlable + test de integración del 429.
```
