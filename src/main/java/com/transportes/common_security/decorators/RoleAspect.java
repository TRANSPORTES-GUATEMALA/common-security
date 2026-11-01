package com.transportes.common_security.decorators;

import java.util.ArrayList;
import java.util.List;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.transportes.common_security.exceptions.SecurityAuthorizationException;

import jakarta.servlet.http.HttpServletRequest;

@Aspect
@Component
public class RoleAspect {

    private static final String AUTH_TYPE_ATTRIBUTE = "authType";
    private static final String USER_ID_ATTRIBUTE = "userId";
    private static final String ROLES_ATTRIBUTE = "roles";

    @Around("@annotation(requireRole)")
    public Object checkRole(ProceedingJoinPoint joinPoint, RequireRole requireRole) throws Throwable {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            throw unauthenticated();
        }

        HttpServletRequest request = attributes.getRequest();
        Object authType = request.getAttribute(AUTH_TYPE_ATTRIBUTE);
        if ("SERVICE".equals(authType)) {
            throw forbidden();
        }
        if (!"USER".equals(authType)) {
            throw unauthenticated();
        }

        Object userId = request.getAttribute(USER_ID_ATTRIBUTE);
        if (!(userId instanceof Long id) || id <= 0) {
            throw unauthenticated();
        }

        Object rolesAttribute = request.getAttribute(ROLES_ATTRIBUTE);
        if (!(rolesAttribute instanceof List<?> roleClaims)) {
            throw forbidden();
        }
        List<String> userRoles = new ArrayList<>(roleClaims.size());
        for (Object role : roleClaims) {
            if (!(role instanceof String text) || text.isBlank()) {
                throw forbidden();
            }
            userRoles.add(text);
        }

        for (String requiredRole : requireRole.value()) {
            if (userRoles.contains(requiredRole)) {
                return joinPoint.proceed();
            }
        }
        throw forbidden();
    }

    private SecurityAuthorizationException unauthenticated() {
        return SecurityAuthorizationException.unauthenticated();
    }

    private SecurityAuthorizationException forbidden() {
        return SecurityAuthorizationException.forbidden();
    }
}
