package com.transportes.common_security.config;

import com.transportes.common_security.exceptions.SecurityAuthorizationException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityAuthorizationExceptionHandler {

    private static final MediaType JSON_UTF8 = new MediaType("application", "json", java.nio.charset.StandardCharsets.UTF_8);

    @ExceptionHandler(SecurityAuthorizationException.class)
    public ResponseEntity<SecurityErrorResponse> handle(SecurityAuthorizationException exception,
                                                        HttpServletRequest request) {
        SecurityErrorResponse response = SecurityErrorResponse.forRequest(
                request, exception.getCode(), exception.getMessage());
        return ResponseEntity.status(exception.getStatus())
                .contentType(JSON_UTF8)
                .body(response);
    }
}
