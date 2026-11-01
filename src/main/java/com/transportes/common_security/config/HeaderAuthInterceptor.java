package com.transportes.common_security.config;

import java.math.BigDecimal;
import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.servlet.HandlerInterceptor;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class HeaderAuthInterceptor implements HandlerInterceptor {

    private static final UrlPathHelper URL_PATH_HELPER = new UrlPathHelper();
    private static final String AUTH_TYPE_ATTRIBUTE = "authType";
    private static final String USER_ID_ATTRIBUTE = "userId";
    private static final String ROLES_ATTRIBUTE = "roles";
    private static final String SERVICE_ATTRIBUTE = "service";

    @Autowired
    private PublicRoutesProperties publicRoutes;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Override
    public boolean preHandle(HttpServletRequest request,
            HttpServletResponse response,
            Object handler) throws IOException {

        clearAuthenticationAttributes(request);
        String path;
        try {
            path = pathWithinContext(request);
        } catch (IllegalArgumentException ignored) {
            return unauthorized(request, response);
        }
        if (!isInternalPath(path) && publicRoutes.isPublic(request.getMethod(), path)) {
            return true;
        }

        String authorization = request.getHeader("Authorization");
        if (authorization == null || authorization.length() <= 7
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return unauthorized(request, response);
        }

        TokenIdentity identity;
        try {
            String token = authorization.substring(7).trim();
            if (token.isEmpty()) {
                return unauthorized(request, response);
            }
            identity = parseToken(token);
        } catch (Exception ignored) {
            return unauthorized(request, response);
        }

        if (isInternalPath(path) && identity.type() != IdentityType.SERVICE) {
            return forbidden(request, response);
        }

        if (identity.type() == IdentityType.SERVICE) {
            request.setAttribute(SERVICE_ATTRIBUTE, identity.subject());
            request.setAttribute(AUTH_TYPE_ATTRIBUTE, IdentityType.SERVICE.name());
            return true;
        }

        request.setAttribute(USER_ID_ATTRIBUTE, identity.userId());
        request.setAttribute(ROLES_ATTRIBUTE, identity.roles());
        request.setAttribute(AUTH_TYPE_ATTRIBUTE, IdentityType.USER.name());
        return true;
    }

    private TokenIdentity parseToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String subject = claims.getSubject();
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();
        if (subject == null || subject.isBlank() || issuedAt == null || expiration == null
                || !expiration.after(issuedAt)) {
            throw new IllegalArgumentException("Invalid token claims");
        }

        Object typeClaim = claims.get("type");
        if (!claims.containsKey("type") || "USER".equals(typeClaim)) {
            return new TokenIdentity(IdentityType.USER, subject,
                    readUserId(claims.get("userId")), readRoles(claims.get("roles")));
        }
        if ("SERVICE".equals(typeClaim)) {
            if (claims.containsKey("userId") || claims.containsKey("roles")) {
                throw new IllegalArgumentException("Service token contains user claims");
            }
            return new TokenIdentity(IdentityType.SERVICE, subject, null, List.of());
        }
        throw new IllegalArgumentException("Unsupported token type");
    }

    private Long readUserId(Object value) {
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException("Invalid user identity");
        }
        try {
            long userId = new BigDecimal(number.toString()).longValueExact();
            if (userId <= 0) {
                throw new IllegalArgumentException("Invalid user identity");
            }
            return userId;
        } catch (NumberFormatException | ArithmeticException exception) {
            throw new IllegalArgumentException("Invalid user identity", exception);
        }
    }

    private List<String> readRoles(Object value) {
        if (!(value instanceof List<?> roleClaims)) {
            throw new IllegalArgumentException("Invalid role claims");
        }
        for (Object role : roleClaims) {
            if (!(role instanceof String text) || text.isBlank() || !text.equals(text.trim())) {
                throw new IllegalArgumentException("Invalid role claims");
            }
        }
        return roleClaims.stream().map(String.class::cast).toList();
    }

    private Key getSignInKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    private String pathWithinContext(HttpServletRequest request) {
        return URL_PATH_HELPER.getLookupPathForRequest(request);
    }

    private boolean isInternalPath(String path) {
        return "/internal/v1".equals(path) || path.startsWith("/internal/v1/");
    }

    private void clearAuthenticationAttributes(HttpServletRequest request) {
        request.removeAttribute(USER_ID_ATTRIBUTE);
        request.removeAttribute(ROLES_ATTRIBUTE);
        request.removeAttribute(SERVICE_ATTRIBUTE);
        request.removeAttribute(AUTH_TYPE_ATTRIBUTE);
    }

    private boolean unauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SecurityErrorResponseWriter.unauthorized(request, response);
        return false;
    }

    private boolean forbidden(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SecurityErrorResponseWriter.forbidden(request, response);
        return false;
    }

    private enum IdentityType {
        USER,
        SERVICE
    }

    private record TokenIdentity(IdentityType type, String subject, Long userId, List<String> roles) {
    }
}
