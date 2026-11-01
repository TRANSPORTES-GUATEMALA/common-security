package com.transportes.common_security.config;

import com.transportes.common_security.exceptions.SecurityAuthorizationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;

final class SecurityErrorResponseWriter {

    private SecurityErrorResponseWriter() {
    }

    static void write(HttpServletRequest request, HttpServletResponse response,
                      HttpStatus status, String code, String message) throws IOException {
        SecurityErrorResponse error = SecurityErrorResponse.forRequest(request, code, message);
        response.setStatus(status.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.getWriter().write(error.toJson());
    }

    static void unauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
        write(request, response, HttpStatus.UNAUTHORIZED,
                SecurityAuthorizationException.AUTH_UNAUTHORIZED, "Authentication required");
    }

    static void forbidden(HttpServletRequest request, HttpServletResponse response) throws IOException {
        write(request, response, HttpStatus.FORBIDDEN,
                SecurityAuthorizationException.AUTH_FORBIDDEN, "Access denied");
    }
}
