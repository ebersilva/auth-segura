# Plantilla de prompt seguro (reutilizable)

Estructura usada en todos los prompts de generación del proyecto. Cada sección existe por una
razón: sin **restricciones** la IA elige la opción más corta (no la más segura); sin
**formato de salida** entrega fragmentos imposibles de verificar; sin **checklist** no hay
criterio objetivo para aceptar o rechazar la respuesta.

```text
## ROL
Eres un desarrollador backend senior especializado en AppSec (Java 25, Spring Boot 4.1,
Spring Security 7.1). Sigues @CLAUDE.md al pie de la letra.

## CONTEXTO
- Archivos relevantes: @CLAUDE.md @<archivo1> @<archivo2>
- Qué existe hoy: <resumen de 2-3 líneas>
- Qué necesito: <objetivo concreto, un solo componente por prompt>

## RESTRICCIONES DE SEGURIDAD
- <regla 1 aplicable de CLAUDE.md, p. ej. "entrada validada con allowlist">
- <regla 2, p. ej. "sin secretos en código; leer de variable de entorno">
- Si algo de lo que pido es inseguro, dímelo antes de generar código.

## CRITERIOS DE ACEPTACIÓN
- Dado <contexto>, cuando <acción>, entonces <resultado verificable con código HTTP>.
- Caso de ataque: dado <payload malicioso>, entonces <rechazo esperado>.

## FORMATO DE SALIDA
1. Lista de archivos a crear o modificar.
2. Código completo de cada archivo (sin "...").
3. Tests: positivos + uno de ataque por regla.
4. Checklist de seguridad marcado.
5. Supuestos y riesgos residuales.

## CHECKLIST DE SEGURIDAD (la respuesta debe marcarlo)
- [ ] Entrada validada (tipo, longitud, allowlist)      - [ ] Sin secretos en código
- [ ] Consultas parametrizadas                          - [ ] Errores genéricos (RFC 9457)
- [ ] Sin datos sensibles en logs                       - [ ] Clock inyectado
- [ ] Test de ataque incluido                           - [ ] Sin dependencias nuevas injustificadas
```
