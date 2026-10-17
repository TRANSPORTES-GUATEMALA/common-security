package com.transportes.common_security.config;

import java.security.Key;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.HandlerInterceptor;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class HeaderAuthInterceptor implements HandlerInterceptor {
    @Autowired
    private PublicRoutesProperties publicRoutes;
    private final AntPathMatcher matcher = new AntPathMatcher();


    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Override
    public boolean preHandle(HttpServletRequest request,
            HttpServletResponse response,
            Object handler) throws Exception {

        String path = request.getRequestURI();
        System.out.println("Interceptando solicitud a: " + path);
        if (isPublic(path, request.getMethod())) {
            return true;
        }
        System.out.println("Requiriendo autenticación para: " + path);

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        try {
            String token = authHeader.substring(7);

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String type = claims.get("type", String.class);
            if (type != null && "SERVICE".equals(type)) {

                String serviceName = claims.getSubject();

                if (serviceName == null) {
                    return unauthorized(response);
                }

                request.setAttribute("service", serviceName);
                request.setAttribute("authType", "SERVICE");

                return true;
            }
            Long userId = Long.valueOf(claims.get("userId").toString());

            List<String> roles;
            Object rolesObj = claims.get("roles");

            if (rolesObj instanceof List<?>) {
                roles = ((List<?>) rolesObj).stream()
                        .map(String::valueOf)
                        .toList();
            } else {
                roles = List.of(rolesObj.toString());
            }

            request.setAttribute("userId", userId);
            request.setAttribute("roles", roles);
            return true;

        } catch (Exception e) {
            System.out.println("TOKEN INVALIDO: " + e.getMessage());
            return unauthorized(response);
        }
    }

    private boolean isPublic(String path, String method) {
        for (String rule : publicRoutes.getRoutes()) {
            String rulePath = rule;

            // Formato "METODO:/ruta" (GET:/api/v1/document-types/**)
            // ** cubre cualquier subruta
            // * un solo segmento de ruta
            int idx = rule.indexOf(':');
            if (idx > 0 && idx < 8) {
                String ruleMethod = rule.substring(0, idx);
                if (!ruleMethod.equalsIgnoreCase(method)) {
                    continue;
                }
                rulePath = rule.substring(idx + 1);
            }

            if (matcher.match(rulePath, path)) {
                return true;
            }
        }
        return false;
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean unauthorized(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }

}
