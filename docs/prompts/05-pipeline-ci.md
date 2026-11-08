# Prompt 05 — Pipeline CI/CD con security gates

```text
## ROL
Eres un ingeniero DevSecOps. Sigue @CLAUDE.md.

## CONTEXTO
@CLAUDE.md @pom.xml. Repositorio en GitHub, build con ./mvnw, JDK 25 (Temurin).

## OBJETIVO
.github/workflows/ci.yml con jobs independientes que funcionen como gates (un PR no se
puede fusionar si alguno falla):
1. build-test: ./mvnw verify (Checkstyle + tests + JaCoCo >= 90 % + SpotBugs/FindSecBugs).
2. codeql: análisis estático semántico (java-kotlin, queries security-extended).
3. dependency-review (solo PR): falla si una dependencia nueva tiene vulnerabilidad >= high.
4. trivy: escaneo de vulnerabilidades del sistema de archivos/dependencias (HIGH, CRITICAL
   -> exit 1) y SARIF a la pestaña Security.
5. gitleaks: detección de secretos en todo el historial.
Más .github/dependabot.yml (maven y github-actions, semanal).

## RESTRICCIONES
- permissions mínimos por job (contents: read; security-events: write solo donde se sube SARIF).
- Acciones fijadas a versión mayor oficial; nada de curl | bash.
- Caché de Maven; concurrency para cancelar ejecuciones viejas.

## FORMATO DE SALIDA
YAML completo + tabla gate -> herramienta -> criterio de falla.
```
