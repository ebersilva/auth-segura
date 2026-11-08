# Configuración de las herramientas de IA

## Herramientas seleccionadas

| Herramienta | Uso en el proyecto | Archivo de configuración |
|---|---|---|
| **Claude Code** (CLI, modelo Claude Opus 5.5) | Herramienta principal: generación de código, pruebas, pipeline y documentación; ejecuta los comandos (`./mvnw`, Trivy, Gitleaks) y lee sus resultados | `CLAUDE.md` |
| **Cursor** | Edición en IDE con autocompletado y chat | `.cursorrules` |
| **GitHub Copilot** | Sugerencias en el IDE, Copilot Chat y revisión de PR en GitHub | `.github/copilot-instructions.md` |

Un equipo real mezcla herramientas: cada desarrollador usa la que prefiere. Por eso las tres
reciben **las mismas reglas**. Si solo una estuviera configurada, el código generado con las otras
dos no tendría las mismas garantías.

## Proceso de configuración

1. **Las reglas antes que el código.** `CLAUDE.md` se escribió antes que cualquier clase. Las diez
   reglas de seguridad salen de OWASP Top 10 2021, ASVS 4.0 (capítulos V2 Autenticación, V3 Sesión
   y V5 Validación) y NIST SP 800-63B (contraseñas).
2. **Reglas verificables.** Cada regla es concreta y comprobable ("Argon2id m=19456, t=2, p=1",
   "patrón `^[a-z0-9._-]{3,30}$`", "falla al arrancar sin `JWT_SECRET`"), no genérica ("usa buenas
   prácticas"). Así la revisión puede decir si una salida cumple o no.
3. **Lista de prohibiciones.** `.cursorrules` y `copilot-instructions.md` incluyen qué **no** generar
   (`permitAll` fuera de `/api/auth/**`, CORS `*`, `Random` para tokens, `Instant.now()`, logs con
   tokens). Los asistentes tienden a sugerir esos atajos porque abundan en su entrenamiento.
4. **Stack fijo.** Se nombran las versiones (Spring Boot 4.1, Security 7.1, Jackson 3) y se
   prohíben librerías alternativas (jjwt). Así se evita la mezcla de APIs de versiones distintas,
   el fallo más común en el reto anterior.
5. **Formato de salida.** Plan → código completo → pruebas (positivas y de ataque) → checklist →
   riesgos. Sin "…" ni fragmentos.
6. **Sincronización.** Las tres configuraciones declaran que `CLAUDE.md` es la fuente común.

## Prompt engineering aplicado

| Técnica | Dónde | Efecto |
|---|---|---|
| **Rol** experto en AppSec | Todos los prompts | Prioriza la seguridad sobre la brevedad y avisa si una petición es insegura |
| **Contexto con `@archivo`** | `@CLAUDE.md` y los archivos tocados | La IA respeta las convenciones existentes |
| **Restricciones explícitas** | Sección *Restricciones de seguridad* | Evita que la IA elija el camino corto (p. ej., guardar el refresh token en claro) |
| **Criterios de aceptación con ataques** | "Dado `' OR '1'='1` → 400" | Cada regla nace con su prueba negativa |
| **Formato de salida fijo** | Sección *Formato de salida* | Respuestas completas y revisables |
| **Checklist de autoverificación** | Plantilla `00` | La IA declara qué cumplió; la revisión humana lo contrasta |
| **Rol adversario** | Prompt `04` (pentester) | Las pruebas buscan romper el sistema, no confirmar que funciona |
| **"No debilites la configuración para que pase una prueba"** | Prompt `04` | Un test en rojo se trata como hallazgo, no como molestia |
| **Un componente por prompt** | Prompts `01`–`05` | Iteraciones cortas y verificables con `./mvnw verify` |

Los prompts completos están en `docs/prompts/` (plantilla `00` y prompts `01` a `05`).

## Verificación de la configuración

La configuración por sí sola no garantiza nada. Lo que la hace efectiva es que el pipeline
comprueba las mismas reglas de forma automática:

| Regla de `CLAUDE.md` | Verificador automático |
|---|---|
| Sin secretos en código | Gitleaks (gate 5) + `StartupWithoutSecretTest` |
| Entrada con allowlist | `InjectionAndXssSecurityTest` (33 casos) |
| Consultas parametrizadas | CodeQL (gate 2) + pruebas de inyección SQL |
| Logs sin datos sensibles / CRLF | FindSecBugs `CRLF_INJECTION_LOGS` (gate 1) + `LogSanitizerTest` |
| Dependencias sin CVE | Trivy (gate 4) + Dependency Review (gate 3) |
| Cobertura ≥ 90 % | JaCoCo (gate 1) |
