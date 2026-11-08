package com.equipo.auth.common.error;

import com.equipo.auth.auth.InvalidCredentialsException;
import com.equipo.auth.auth.InvalidTokenException;
import com.equipo.auth.auth.RegistrationConflictException;
import com.equipo.auth.auth.WeakPasswordException;
import com.equipo.auth.ratelimit.RateLimitExceededException;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Traduce excepciones a RFC 9457 ({@code application/problem+json}) con mensajes genéricos: nunca
 * incluye stack traces, nombres de clases, SQL ni el valor rechazado (podría ser un payload malicioso).
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    static final String INVALID_DATA = "La solicitud contiene datos inválidos";

    /** Errores del esquema: uno por campo, ordenados para respuestas deterministas. */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldErrorDetail> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> new FieldErrorDetail(e.getField(), e.getDefaultMessage()))
                .sorted(Comparator.comparing(FieldErrorDetail::field).thenComparing(FieldErrorDetail::message))
                .toList();
        return ResponseEntity.badRequest().body(validationProblem(errors));
    }

    /** JSON mal formado, tipos incorrectos o propiedades no permitidas (mass assignment). */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return ResponseEntity.badRequest().body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                "El cuerpo no es un JSON válido o contiene campos no permitidos"));
    }

    /** Contraseña fuera de política. */
    @ExceptionHandler(WeakPasswordException.class)
    public ProblemDetail handleWeakPassword(WeakPasswordException ex) {
        return validationProblem(List.of(new FieldErrorDetail("password", ex.getMessage())));
    }

    /** Login fallido (mensaje único). */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ProblemDetail handleInvalidCredentials(InvalidCredentialsException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    /** Refresh token o sesión inválidos. */
    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail handleInvalidToken(InvalidTokenException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    /** Dos rotaciones simultáneas del mismo refresh token: la perdedora se trata como token inválido. */
    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ProblemDetail handleConcurrentRotation(ObjectOptimisticLockingFailureException ex) {
        LOG.warn("SECURITY refresh_token_concurrent_use");
        return handleInvalidToken(new InvalidTokenException());
    }

    /** Usuario o correo duplicados. */
    @ExceptionHandler(RegistrationConflictException.class)
    public ProblemDetail handleConflict(RegistrationConflictException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    /** Límite de peticiones superado: 429 con {@code Retry-After}. */
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ProblemDetail> handleRateLimit(RateLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(ex.getRetryAfterSeconds()))
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage()));
    }

    /** Cualquier otro error: 500 sin detalles internos; el detalle queda solo en el log. */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception ex) {
        LOG.error("Error no controlado", ex);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Error interno del servidor");
    }

    private static ProblemDetail validationProblem(List<FieldErrorDetail> errors) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, INVALID_DATA);
        problem.setProperty("errors", errors);
        return problem;
    }
}
