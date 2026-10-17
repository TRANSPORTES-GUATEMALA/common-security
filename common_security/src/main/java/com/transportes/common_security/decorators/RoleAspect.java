package com.transportes.common_security.decorators;

import java.util.Arrays;
import java.util.List;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import com.transportes.common_security.exceptions.InvalidUserException;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Aspect
@Component
public class RoleAspect {

    @Around("@annotation(requireRole)")
    public Object checkRole(ProceedingJoinPoint joinPoint, RequireRole requireRole) throws Throwable {

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .getRequestAttributes())
                .getRequest();

        Object rolesObj = request.getAttribute("roles");

        if (rolesObj == null) {
            throw new InvalidUserException("User unauthorized");
        }

        List<String> userRoles;

        if (rolesObj instanceof List<?>) {
            userRoles = ((List<?>) rolesObj).stream()
                    .map(String::valueOf)
                    .toList();
        } else {
            userRoles = Arrays.asList(rolesObj.toString().split(","));
        }

        List<String> requiredRoles = Arrays.asList(requireRole.value());

        boolean hasRole = userRoles.stream().anyMatch(requiredRoles::contains);

        if (!hasRole) {
            throw new InvalidUserException("Access denied");
        }

        return joinPoint.proceed();
    }
}