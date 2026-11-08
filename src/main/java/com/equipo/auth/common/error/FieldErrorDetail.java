package com.equipo.auth.common.error;

/**
 * Error de validación de un campo.
 *
 * @param field   nombre del campo
 * @param message mensaje para el cliente
 */
public record FieldErrorDetail(String field, String message) {
}
