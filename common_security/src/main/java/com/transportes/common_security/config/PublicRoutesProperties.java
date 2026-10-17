package com.transportes.common_security.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties (prefix = "security.public")
public class PublicRoutesProperties {
  
    private List<String> routes = new ArrayList<>(List.of(
            "/api/v1/auth/**",
            "GET:/api/v1/document-types/**",
            "/api/v3/api-docs/**"
    ));

    public List<String> getRoutes() {
        return routes;
    }

    public void setRoutes(List<String> routes) {
        this.routes = routes;
    }
}
