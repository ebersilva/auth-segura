# Evidencia del proceso de desarrollo asistido por IA

**Autor:** Eber Silva Garcia · **Fecha:** 2026-11-07 · **Herramienta principal:** Claude Code (CLI)
con Claude Opus 5.5 · **Configuración:** `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`

## 1. Método

Cada iteración siguió el mismo ciclo:

1. **Prompt estructurado** (`docs/prompts/0X-*.md`): rol, contexto con `@archivo`, restricciones de
   seguridad, criterios de aceptación con casos de ataque, formato de salida y checklist.
2. **Generación** del componente y de sus pruebas en la misma iteración.
3. **Verificación automática**: `./mvnw verify` (Checkstyle, pruebas, JaCoCo, SpotBugs + FindSecBugs)
   y, desde la iteración 6, Trivy, Gitleaks y PIT.
4. **Revisión humana** de cada salida contra el checklist; un test en rojo se trata como hallazgo.

> Principio aplicado: *la IA propone, las herramientas verifican y la persona decide*. Ninguna
> salida de la IA se aceptó porque "parecía correcta"; todas pasaron por un verificador objetivo.

## 2. Iteraciones

| # | Prompt / objetivo | Resultado de la verificación | Corrección |
|---|---|---|---|
| 1 | Configuración de IA (antes del código): reglas de seguridad para las tres herramientas y prompts `00`–`05` | Revisión manual contra OWASP, ASVS y NIST | — |
| 2 | `01-modulo-autenticacion`: entidad, DTOs con esquema, registro, login, Argon2id | Checkstyle: `AuthService` con 10 parámetros (máx. 7); clase `JwtValidators` con el mismo nombre que una de Spring | Se dividió en `RegistrationService` + `LoginAttemptGuard` + `AuthService`; se renombró a `AccessTokenValidators` |
| 3 | `02-jwt-y-refresh`: emisión y validación de JWT, rotación, logout | Prueba de integración: **11/12**. `accessToken_expiraALos15Minutos`: *Status expected:<401> but was:<200>* | **Hallazgo H1** (ver §3) → `strictExpiry` |
| 4 | `04-pruebas-seguridad`: inyección, XSS, JWT, fuerza bruta, reutilización | 71 pruebas, 2 en rojo | Ambos eran errores **de las pruebas**: el helper no escapaba `\n` y se comparaba `Content-Type` sin `charset`. El código de producción no se tocó |
| 5 | Pruebas unitarias + `verify` completo | 147/147 OK, cobertura OK, **SpotBugs bloqueó el build con 23 hallazgos** (`logs/01-…`) | **H2**: 16 corregidos en código, 7 excluidos con justificación → 0 |
| 6 | Mutation testing con PIT | **72 %** (100/138), 30 sin cobertura, 8 sobrevivientes | Pruebas nuevas → **98 %** (127/129). Un sobreviviente reveló **H3** (request smuggling) |
| 7 | `05-pipeline-ci` + escáneres locales con podman | Trivy: 429 de Maven Central; luego **9 CVE HIGH/CRITICAL** (`logs/02-…`). Gitleaks: 9 falsos positivos. actionlint: 0 | **H4**: Spring Boot 4.1.2 → 0 CVE. `.gitleaks.toml` → 0. **H5**: etiqueta de imagen inventada |
| 8 | Prueba manual con curl contra la API real (`logs/07-…`) | `createdAt` distinto entre registro y perfil; el 429 por usuario no dejaba rastro en los logs | **H6** y **H7** con pruebas de regresión |
| 9 | Escaneo final antes de la entrega | Gitleaks: contraseña de ejemplo en `README.md` | **H8** → 0 |
| 10 | Verificación del zip en una carpeta limpia | 10 pruebas en rojo: dependían del orden de ejecución (`logs/12-…`) | **H9** → verde en orden alfabético, inverso y aleatorio |
| — | Resultado final | 170/170 · 99,6 % líneas · 98,3 % ramas · PIT 98 % · Checkstyle 0 · SpotBugs 0 · Trivy 0 · Gitleaks 0 | `logs/09-verify-final.log` |

## 3. Hallazgos de seguridad y calidad

Esta sección es la evidencia más importante del reto: cada hallazgo lo introdujo la IA, o la IA
no lo vio, y lo detectó un verificador automático o una prueba manual.

### H1 — El access token seguía siendo válido en el instante exacto de `exp`

- **Detección:** la prueba de integración avanza el reloj controlable 15:00 y espera 401; recibió 200.
- **Causa:** `JwtTimestampValidator` de Spring Security compara con `now.isAfter(exp)`. La RFC 7519 §4.1.4
  exige que el instante actual sea **anterior** a `exp`. La IA confió en el validador por defecto.
- **Corrección:** `AccessTokenValidators.strictExpiry(clock)` exige `now < exp`.
  Pruebas: `strictExpiry_rechazaEnElInstanteExactoDeExp` y `decode_enElInstanteDeExpiracion_esRechazado`.
- **Lección:** el reloj inyectado (regla 10 de `CLAUDE.md`) es lo que permitió probar el límite exacto.
  Con `Instant.now()` este caso no se habría podido probar.

### H2 — 23 hallazgos de SpotBugs + Find Security Bugs

| Patrón | Cant. | Decisión |
|---|---|---|
| `CRLF_INJECTION_LOGS` | 7 | **Corregido**: `LogSanitizer` reemplaza los caracteres de control (CWE-117). FindSecBugs lo reconoce como sanitizador |
| `NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE` (`getSubject()`, `getExpiresAt()`) | 4 | **Corregido**: `TokenClaims.userId()` y validación explícita en `logout`; no se confía en que el decoder siempre los traiga |
| `EI_EXPOSE_REP/REP2` (lista CORS mutable) | 2 | **Corregido**: `List.copyOf` en el constructor compacto |
| `CT_CONSTRUCTOR_THROW` (`RateLimiter`) | 1 | **Corregido**: clase `final` (sin finalizer attack) |
| `SPRING_CSRF_PROTECTION_DISABLED` (High) | 1 | **Excluido con justificación**: API stateless con bearer token |
| `XSS_SERVLET` (`ProblemJson`) | 1 | **Excluido**: escribe JSON escapado; lo prueban `ProblemJsonTest` y un test de XSS en la URI |
| `SPRING_ENDPOINT`, `SERVLET_HEADER` | 7 | **Excluidos**: informativos (inventario / solo comprueba si la cabecera existe) |

Las 16 correcciones las propuso la IA a partir del reporte. Las 7 exclusiones se revisaron una
por una: ninguna es global y cada una tiene una prueba que la respalda (`config/spotbugs/exclude.xml`).

### H3 — Request smuggling revelado por mutation testing

- **Detección:** sobrevivió el mutante `length < 0` → `length <= 0` en `RequestSizeFilter`.
- **Análisis:** el mutante sobrevivía porque ninguna prueba enviaba `Transfer-Encoding` con
  `Content-Length: 0`, y el código original **dejaba pasar** esa combinación. Ese par de cabeceras
  es el vector de *HTTP request smuggling* (RFC 9112 §6.1).
- **Corrección:** cualquier `Transfer-Encoding` responde 411. Prueba:
  `requestSize_transferEncodingConContentLength_responde411`.
- **Lección:** la cobertura de líneas era del 99 % y no mostraba nada. PIT encontró el hueco
  porque mide si las pruebas **detectan** un cambio, no si ejecutan la línea.

Los otros 7 sobrevivientes de la primera corrida también eran pruebas débiles. Las pruebas de
enmascaramiento solo verificaban que el `toString()` *no* contuviera la contraseña, así que un
`toString()` vacío también pasaba. Además, ninguna prueba comprobaba que la lista de revocación
purgara los tokens expirados, es decir, que la memoria quedara acotada.

Los 2 sobrevivientes finales son **mutantes equivalentes**. En uno, `elapsed >= 0` suma 0
fichas, igual que `elapsed > 0`. En el otro, el operador ternario solo cambia el texto del log.

### H4 — Dependencias con 9 CVE (4 CRITICAL) en la versión elegida por la IA

- **Detección:** Trivy 0.76.1 sobre `pom.xml` (`logs/02-trivy-gate-bloquea-9-cve-boot-4.1.1.log`).
  La IA eligió Spring Boot 4.1.1 porque era la versión del proyecto del reto 2. Esa versión arrastra
  Tomcat 11.0.24 (CVE-2026-65182 y otros: evasión de restricciones de seguridad) y Jackson 3.1.5
  (varios DoS).
- **Corrección:** Spring Boot **4.1.2** (Tomcat 11.0.27, Jackson 3.1.7, Spring Security 7.1.2). Se
  prefirió subir el parent (parche oficial, la misma acción que haría Dependabot) a sobrescribir
  versiones transitivas sueltas. Resultado: 0 vulnerabilidades (`logs/04-…`).
- **Incidente operativo:** la primera ejecución de Trivy recibió `429 Too Many Requests` de Maven
  Central. Se resolvió montando `~/.m2` en el contenedor, como recomienda el propio Trivy, y quedó
  documentado en `docs/ci-cd.md`.

### H5 — La IA inventó la etiqueta de una imagen de contenedor

Al escribir el workflow, la IA fijó `aquasec/trivy:0.69.3` sin comprobar que existiera. Antes de
ejecutarlo se consultó la API de Docker Hub: la versión vigente era la 0.76.x. Se cambió a
`0.76.1`, una versión real y estable, y se verificó también `zricethezav/gitleaks:v8.30.1`.
Una etiqueta inexistente habría roto el gate. Peor aún, una etiqueta *typosquatted* habría metido
código ajeno en el pipeline.

### H6 — `createdAt` distinto entre el registro y el perfil (bug repetido del reto 2)

- **Detección:** la prueba manual con curl devolvió `…186883078Z` al registrar y `…186883Z` en `/me`.
- **Causa:** la respuesta del registro sale de la entidad en memoria (nanosegundos) y la del perfil
  de H2 (microsegundos). **Es el mismo bug que se corrigió en el reto 2**, y la IA lo volvió a
  introducir: no conserva lecciones entre proyectos si no están escritas en su contexto.
- **Corrección:** truncar a milisegundos en `RegistrationService`. La prueba
  `registro_yPerfil_devuelvenElMismoCreatedAt` usa un reloj con nanosegundos. Se comprobó que
  **falla sin el fix** (*expected …123456789Z but was …123457Z*) y pasa con él.

### H7 — Hueco en el registro de eventos (A09)

Al revisar los logs de la app real (`logs/08-…`), se vio que el 429 por usuario del login no
dejaba evento: un ataque de fuerza bruta frenado por el limitador no habría quedado registrado.
Se agregó `SECURITY login_rate_limited user=… retry_after=…`.

### H8 — Contraseña de ejemplo en la documentación

En el último escaneo antes de la entrega, Gitleaks marcó 2 hallazgos en `README.md`: los ejemplos de curl
que generó la IA incluían una contraseña literal. No es un secreto de producción, pero las credenciales
de ejemplo se copian y terminan en uso real, y entrenan el mal hábito. Se reemplazaron por
`read -rsp 'Contraseña: ' PASSWORD` y `$PASSWORD`. Escaneo final: 0 (`logs/05-gitleaks-final-0-secretos.log`).
El gate funcionó sobre la documentación, no solo sobre el código.

### H9 — Pruebas dependientes del orden de ejecución

- **Detección:** al verificar el zip de entrega en una carpeta limpia, el sistema de archivos entregó las clases en otro
  orden y fallaron 10 pruebas de integración con 500 (*Table "USERS" not found*). En la carpeta original pasaban.
- **Causa:** todos los contextos de Spring compartían la base `jdbc:h2:mem:auth` con `ddl-auto=create-drop`.
  `StartupWithoutSecretTest` arranca la aplicación real, que falla a propósito, y al cerrarse **borraba las tablas
  de la base compartida**. En orden alfabético, otro contexto las volvía a crear justo después, y eso ocultaba el problema.
- **Corrección:** base H2 propia por contexto (`jdbc:h2:mem:${random.uuid}`) y otra para la prueba de arranque.
  Verificado con `-Dsurefire.runOrder=reversealphabetical`, `alphabetical` y `random`.
- **Lección:** "en mi máquina pasa" no es evidencia. Verificar el artefacto que realmente se entrega, en un entorno
  limpio, encontró un defecto que 170 pruebas en verde no mostraban.

## 4. Prompts utilizados

Los prompts estructurados completos están en `docs/prompts/`. Ejemplo representativo (prompt `02`, resumido):

```text
## ROL
Eres un desarrollador backend senior especializado en AppSec. Sigue @CLAUDE.md.
## CONTEXTO
@CLAUDE.md @src/main/java/com/equipo/auth/auth/AuthService.java
El login ya valida credenciales. Falta emitir tokens y proteger /api/users/me.
## RESTRICCIONES DE SEGURIDAD
- Access token JWT HS256 de 15 min con iss, aud, sub, exp, iat, jti. Secreto desde JWT_SECRET
  (>= 32 bytes); si falta o es corto, la aplicación NO arranca.
- Refresh token: 32 bytes de SecureRandom; en la BD solo su SHA-256. Un solo uso; si llega uno ya
  usado -> revocar TODA la familia y 401.
## CRITERIOS DE ACEPTACIÓN
- Token con alg=none, firma alterada, expirado, otro issuer u otra audiencia -> 401.
- Tras logout, el access token anterior -> 401.
## FORMATO DE SALIDA
Archivos completos + tests de cada rechazo + checklist + riesgos residuales.
```

Prompts de seguimiento usados durante la depuración:

- *"Esta prueba espera 401 al minuto 15:00 y recibe 200. Antes de corregir, explica qué validador
  decide la expiración y compáralo con la RFC 7519 §4.1.4."* → llevó a H1 sin debilitar la prueba.
- *"SpotBugs reporta 23 hallazgos [reporte]. Clasifícalos en: vulnerabilidad real, defensa en
  profundidad y falso positivo. No excluyas ninguno sin una justificación y una prueba."* → H2.
- *"Este mutante sobrevivió: `length < 0` → `length <= 0`. ¿Qué entrada distingue los dos casos y
  es esa entrada un ataque?"* → H3.
- *"Trivy encontró estos CVE. ¿Se corrigen subiendo el parent o sobrescribiendo versiones? Indica
  qué versión del parent los corrige y verifícalo en Maven Central."* → H4.

## 5. Lecciones aprendidas

**Sobre calidad**
1. **Cobertura ≠ calidad.** Con 99 % de líneas, PIT encontró 8 pruebas débiles y un hueco de
   seguridad real (H3). Las dos métricas se complementan.
2. **Un reloj inyectable es requisito de seguridad, no solo de testabilidad.** Sin él no se puede
   probar la expiración exacta (H1), la recarga del rate limiter ni el desbloqueo de cuenta.
3. **Probar la aplicación real encuentra lo que las pruebas no buscan.** H6 y H7 salieron de
   curl y de leer los logs, igual que en el reto 2.

**Sobre seguridad**
4. **Las herramientas encuentran clases de error que la IA no ve en el código que ella misma
   genera.** La IA escribió logs vulnerables a CRLF aunque `CLAUDE.md` pedía cuidar los logs;
   FindSecBugs los encontró en segundos.
5. **El riesgo de la cadena de suministro es real y llega solo.** Ninguna línea propia tenía una
   vulnerabilidad, pero el proyecto tenía 4 CVE críticos heredados (H4). Sin Trivy o Dependabot,
   nadie lo habría notado.
6. **Excluir es una decisión, no un atajo.** Cada exclusión de SpotBugs y Gitleaks quedó acotada,
   justificada y respaldada por una prueba.

**Sobre el uso de IA**
7. **Las reglas escritas funcionan; las implícitas no.** Lo que estaba en `CLAUDE.md` (Argon2id,
   allowlists, `Clock`, fail fast del secreto) salió bien a la primera. Lo que no estaba (truncar
   timestamps, registrar el 429) se repitió como error.
8. **La IA alucina datos verificables.** La etiqueta de imagen inventada (H5) es el ejemplo más claro.
   Versiones, CVE y etiquetas se verifican contra la fuente (Maven Central, Docker Hub) antes de usarlos.
9. **Pedir el análisis antes que la solución** evitó "arreglar" las pruebas en lugar del código.
   En la iteración 4 los dos rojos eran errores de las pruebas, y en la 3 era un error del código:
   la única forma de distinguirlos es entender la causa.

## 6. Reflexión crítica: IA y desarrollo seguro

La IA multiplicó la velocidad: 47 archivos de producción, 29 de pruebas (170 casos), un pipeline de cinco gates y la
documentación en una sesión. También multiplicó la **superficie que hay que verificar**. Con
este volumen, revisar línea por línea no escala. La revisión humana se vuelve viable porque el
pipeline hace la parte mecánica (estilo, cobertura, patrones inseguros, CVE, secretos), y la
persona se concentra en decisiones: aceptar o no un riesgo, si una exclusión está justificada, si
una prueba prueba lo correcto.

Tres riesgos que este reto hizo concretos:

- **Confianza transferida.** La IA genera código que *parece* experto, con comentarios de OWASP,
  RFC y ASVS. Aun así, delegó la expiración en un validador con un error de límite (H1) y heredó
  dependencias vulnerables (H4). El tono de autoridad no sustituye la verificación.
- **Errores repetidos.** Sin memoria entre proyectos, la IA repite lo que ya se había corregido
  (H6). La mitigación es institucional: documentar cada lección en `CLAUDE.md` para que forme parte
  del contexto. Tras este reto se agregarían dos reglas: "truncar instantes a la precisión de la
  base de datos" y "todo rechazo de seguridad deja un evento".
- **Cadena de suministro asistida.** Una etiqueta de imagen inventada (H5) o una dependencia
  sugerida sin revisar son vectores de ataque que la IA puede introducir con total naturalidad.
  Fijar versiones, verificarlas y escanearlas deja de ser opcional.

Conclusión: la IA es un **acelerador que exige más disciplina de verificación, no menos**. En este
reto, la seguridad no vino del modelo. Vino del sistema que se construyó a su alrededor: reglas
explícitas, prompts con criterios de ataque, pruebas adversarias y gates automáticos que no
negocian. El desarrollador deja de escribir cada línea y pasa a diseñar y auditar ese sistema.
Esa responsabilidad no se puede delegar.
