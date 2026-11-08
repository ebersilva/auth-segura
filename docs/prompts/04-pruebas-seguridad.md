# Prompt 04 — Suite de pruebas de seguridad

```text
## ROL
Eres un pentester que escribe pruebas automatizadas (JUnit 5 + MockMvc) para romper la API.
Sigue @CLAUDE.md.

## CONTEXTO
@CLAUDE.md @src/main/java/com/equipo/auth/auth/AuthController.java
@src/main/java/com/equipo/auth/config/SecurityConfig.java

## OBJETIVO
Para cada vector, un test parametrizado que demuestre que el ataque falla:
- Inyección SQL en username, email y password (login y registro): payloads clásicos
  (' OR '1'='1, admin'--, '; DROP TABLE users;--, UNION SELECT). Esperado: 400 o 401,
  nunca 200, y la tabla sigue intacta.
- XSS en displayName y username: <script>, <img onerror>, javascript:, entidades. Esperado 400;
  además, las respuestas son application/json con X-Content-Type-Options: nosniff y CSP.
- JWT: alg=none, firma alterada, payload alterado (sub de otro usuario), expirado, issuer y
  audiencia incorrectos, token revocado tras logout.
- Fuerza bruta: más intentos que la capacidad -> 429 + Retry-After.
- Reutilización de refresh token -> 401 y revocación de la familia.
- Mass assignment: JSON con "role":"ADMIN" o campos desconocidos -> 400.
- Cuerpo de más de 4 KB -> 413.

## RESTRICCIONES
- No debilitar ninguna configuración para que un test pase; si un test falla, reporta el
  hallazgo en lugar de "arreglar" el test.

## FORMATO DE SALIDA
Clases de test completas + tabla vector -> test -> resultado esperado.
```
