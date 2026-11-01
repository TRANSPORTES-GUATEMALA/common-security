package com.transportes.common_security.config;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;

record PublicRouteRule(HttpMethod method, String path) {

    private static final Pattern VALID_SEGMENT = Pattern.compile("[A-Za-z0-9._~-]+|\\*|\\*\\*");
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    static Optional<PublicRouteRule> parse(String value) {
        if (value == null || !value.equals(value.trim())) {
            return Optional.empty();
        }

        int separator = value.indexOf(':');
        if (separator <= 0 || separator == value.length() - 1) {
            return Optional.empty();
        }

        String methodValue = value.substring(0, separator).toUpperCase(Locale.ROOT);
        String path = value.substring(separator + 1);
        HttpMethod method;
        try {
            method = HttpMethod.valueOf(methodValue);
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }

        if (!isValidPath(path)) {
            return Optional.empty();
        }
        return Optional.of(new PublicRouteRule(method, path));
    }

    boolean matches(String requestMethod, String requestPath) {
        return method.matches(requestMethod) && PATH_MATCHER.match(path, requestPath);
    }

    private static boolean isValidPath(String path) {
        if (path == null || !path.startsWith("/") || path.contains("//") || path.length() < 2) {
            return false;
        }

        String[] segments = path.substring(1).split("/", -1);
        boolean hasLiteralSegment = false;
        for (int index = 0; index < segments.length; index++) {
            String segment = segments[index];
            if (!VALID_SEGMENT.matcher(segment).matches() || ".".equals(segment) || "..".equals(segment)) {
                return false;
            }
            if ("**".equals(segment) && index != segments.length - 1) {
                return false;
            }
            if (!"*".equals(segment) && !"**".equals(segment)) {
                hasLiteralSegment = true;
            }
        }
        return hasLiteralSegment;
    }
}
