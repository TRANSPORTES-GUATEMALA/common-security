package com.transportes.common_security.exceptions;

import org.springframework.http.HttpStatus;

public final class SecurityAuthorizationException extends RuntimeException {

    public static final String AUTH_UNAUTHORIZED = "AUTH_UNAUTHORIZED";
    public static final String AUTH_FORBIDDEN = "AUTH_FORBIDDEN";

    private final HttpStatus status;
    private final String code;

    private SecurityAuthorizationException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public static SecurityAuthorizationException unauthenticated() {
        return new SecurityAuthorizationException(HttpStatus.UNAUTHORIZED,
                AUTH_UNAUTHORIZED, "Authentication required");
    }

    public static SecurityAuthorizationException forbidden() {
        return new SecurityAuthorizationException(HttpStatus.FORBIDDEN,
                AUTH_FORBIDDEN, "Access denied");
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }
}
