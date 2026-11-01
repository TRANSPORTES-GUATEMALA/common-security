package com.transportes.common_security.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import java.util.regex.Pattern;

public record SecurityErrorResponse(String code, String message, String correlationId) {

    private static final Pattern SAFE_CORRELATION_ID = Pattern.compile("[A-Za-z0-9._-]{1,128}");

    static SecurityErrorResponse forRequest(HttpServletRequest request, String code, String message) {
        Object contextId = request.getAttribute("correlationId");
        String correlationId = contextId instanceof String value && SAFE_CORRELATION_ID.matcher(value).matches()
                ? value
                : UUID.randomUUID().toString();
        return new SecurityErrorResponse(code, message, correlationId);
    }

    String toJson() {
        return "{\"code\":" + quote(code)
                + ",\"message\":" + quote(message)
                + ",\"correlationId\":" + quote(correlationId) + "}";
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
