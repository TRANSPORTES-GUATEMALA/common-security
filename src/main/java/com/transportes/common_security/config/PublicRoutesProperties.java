package com.transportes.common_security.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.public")
public class PublicRoutesProperties {

    private List<String> routes = new ArrayList<>();

    public List<String> getRoutes() {
        return routes;
    }

    public void setRoutes(List<String> routes) {
        this.routes = routes == null ? new ArrayList<>() : new ArrayList<>(routes);
    }

    List<PublicRouteRule> validRules() {
        return routes.stream()
                .map(PublicRouteRule::parse)
                .flatMap(java.util.Optional::stream)
                .toList();
    }

    boolean isPublic(String method, String path) {
        return validRules().stream().anyMatch(rule -> rule.matches(method, path));
    }
}
