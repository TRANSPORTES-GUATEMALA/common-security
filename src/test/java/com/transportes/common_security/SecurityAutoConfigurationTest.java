package com.transportes.common_security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.http.MediaType;

import com.transportes.common_security.decorators.RequireRole;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@SpringBootTest(
        classes = SecurityAutoConfigurationTest.TestApplication.class,
        properties = {
                "security.jwt.secret-key=bXktc2VjcmV0LWtleS1mb3ItdGVzdGluZy0wMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==",
                "security.public.routes[0]=GET:/api/v1/public/route",
                "security.public.routes[1]=POST:/api/v1/auth/login",
                "security.public.routes[2]=GET:/openapi/v3/**",
                "security.public.routes[3]=/api/v1/auth/**",
                "security.public.routes[4]=GET:/internal/v1/**",
                "spring.autoconfigure.exclude=org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration",
                "logging.level.root=INFO"
        })
@AutoConfigureMockMvc
class SecurityAutoConfigurationTest {

    private static final String SECRET =
            "bXktc2VjcmV0LWtleS1mb3ItdGVzdGluZy0wMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==";
    private static final Key SIGNING_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
    private static final Key OTHER_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(
            "YW5vdGhlci1zZWNyZXQta2V5LXNpemVkLWF0LTMyaHl0ZXM="));

    @Autowired
    private MockMvc mockMvc;

    @Test
    void acceptsLegacyUserTokenAndKeepsHeaderValuesUntrusted() throws Exception {
        mockMvc.perform(get("/api/v1/whoami")
                        .header("Authorization", bearer(userToken(17, List.of("CUSTOMER"), null)))
                        .header("X-User-Id", "999")
                        .header("X-Roles", "ADMIN,CASHIER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authType").value("USER"))
                .andExpect(jsonPath("$.userId").value(17))
                .andExpect(jsonPath("$.roles[0]").value("CUSTOMER"))
                .andExpect(jsonPath("$.service").doesNotExist());

        mockMvc.perform(get("/v1/protected"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/v1"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/v1/protected")
                        .header("Authorization", bearer(userToken(17, List.of("CUSTOMER"), "USER"))))
                .andExpect(status().isOk());
    }

    @Test
    void acceptsServiceTokensWithoutCreatingUserPrivileges() throws Exception {
        mockMvc.perform(get("/api/v1/whoami")
                        .header("Authorization", bearer(serviceToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authType").value("SERVICE"))
                .andExpect(jsonPath("$.service").value("commerce-service"))
                .andExpect(jsonPath("$.userId").doesNotExist())
                .andExpect(jsonPath("$.roles").doesNotExist());

        mockMvc.perform(get("/internal/v1/protected")
                        .header("Authorization", bearer(serviceToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authType").value("SERVICE"));

        mockMvc.perform(get("/internal/v1/protected"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/internal/v1/protected")
                        .header("Authorization", bearer(userToken(17, List.of("ADMIN"), null))))
                .andExpect(status().isForbidden()).andExpect(securityError("AUTH_FORBIDDEN", "Access denied"));
        mockMvc.perform(get("/internal/v1;version=1/protected")
                        .header("Authorization", bearer(userToken(17, List.of("ADMIN"), null))))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void rejectsMissingInvalidExpiredAndStructurallyInvalidTokens() throws Exception {
        mockMvc.perform(get("/api/v1/protected"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/protected").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/protected")
                        .header("Authorization", bearer(userToken(17, List.of("ADMIN"), null, OTHER_KEY))))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/protected")
                        .header("Authorization", bearer(userToken(17, List.of("ADMIN"), null,
                                SIGNING_KEY, Instant.now().minusSeconds(30), true))))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/protected")
                        .header("Authorization", bearer(signedToken(
                                Map.of("userId", 17, "roles", List.of("ADMIN")), false, SIGNING_KEY))))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/protected")
                        .header("Authorization", bearer(signedToken(
                                Map.of("userId", 17, "roles", List.of("ADMIN"), "exp", "invalid"),
                                false, SIGNING_KEY))))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));

        for (String token : List.of(
                signedToken(Map.of("roles", List.of("ADMIN")), true, SIGNING_KEY),
                userToken("not-a-number", List.of("ADMIN"), null),
                userToken(17, "ADMIN", null),
                userToken(17, List.of("ADMIN", 7), null),
                userToken(17, List.of("ADMIN"), "UNKNOWN"),
                userToken(17, List.of("ADMIN"), "SERVICE"),
                signedToken(Map.of("type", "SERVICE", "userId", 17, "roles", List.of("ADMIN")),
                        true, SIGNING_KEY))) {
            mockMvc.perform(get("/api/v1/protected").header("Authorization", bearer(token)))
                    .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        }
    }

    @Test
    void authorizesPublicRoutesByMethodAndExactConfiguredPattern() throws Exception {
        mockMvc.perform(get("/api/v1/public/route"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/public/route"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/public/route/child"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(post("/api/v1/auth/login"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/auth/secret"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/openapi/v3/schema"))
                .andExpect(status().isOk());
    }

    @Test
    void requireRoleReturns401WithoutIdentityAnd403WithoutRoleOverHttp() throws Exception {
        mockMvc.perform(get("/api/v1/role/cashier"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
        mockMvc.perform(get("/api/v1/role/cashier")
                        .header("Authorization", bearer(userToken(17, List.of("CASHIER"), null))))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/role/cashier")
                        .header("Authorization", bearer(userToken(17, List.of("CUSTOMER"), null)))
                        .header("X-Roles", "CASHIER"))
                .andExpect(status().isForbidden()).andExpect(securityError("AUTH_FORBIDDEN", "Access denied"));
        mockMvc.perform(get("/api/v1/role/cashier")
                        .header("Authorization", bearer(serviceToken()))
                        .header("X-Roles", "CASHIER"))
                .andExpect(status().isForbidden()).andExpect(securityError("AUTH_FORBIDDEN", "Access denied"));
    }

    @Test
    void servletContextPathDoesNotBypassAuthentication() throws Exception {
        mockMvc.perform(get("/tenant/api/v1/protected")
                        .contextPath("/tenant")
                        .servletPath("/api/v1/protected"))
                .andExpect(status().isUnauthorized()).andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"));
    }

    @Test
    void generatesDistinctCorrelationIdsAndIgnoresClientCorrelationHeader() throws Exception {
        MvcResult first = mockMvc.perform(get("/api/v1/protected")
                        .header("X-Correlation-Id", "client-controlled"))
                .andExpect(status().isUnauthorized())
                .andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"))
                .andReturn();
        MvcResult second = mockMvc.perform(get("/api/v1/protected"))
                .andExpect(status().isUnauthorized())
                .andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"))
                .andReturn();
        String firstId = jsonString(first, "$.correlationId");
        String secondId = jsonString(second, "$.correlationId");
        assertNotEquals("client-controlled", firstId);
        assertNotEquals(firstId, secondId);

        MvcResult serverContext = mockMvc.perform(get("/api/v1/protected")
                        .requestAttr("correlationId", "trusted-context-17"))
                .andExpect(status().isUnauthorized())
                .andExpect(securityError("AUTH_UNAUTHORIZED", "Authentication required"))
                .andReturn();
        assertEquals("trusted-context-17", jsonString(serverContext, "$.correlationId"));
    }

    private static ResultMatcher securityError(String expectedCode, String expectedMessage) {
        return result -> {
            String contentType = result.getResponse().getContentType();
            assertTrue(contentType != null && MediaType.APPLICATION_JSON.isCompatibleWith(
                    MediaType.parseMediaType(contentType)));
            assertEquals(StandardCharsets.UTF_8.name(), result.getResponse().getCharacterEncoding());
            String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
            Map<?, ?> payload = com.jayway.jsonpath.JsonPath.read(body, "$");
            assertEquals(Set.of("code", "message", "correlationId"), payload.keySet());
            assertEquals(expectedCode, com.jayway.jsonpath.JsonPath.read(body, "$.code"));
            assertEquals(expectedMessage, com.jayway.jsonpath.JsonPath.read(body, "$.message"));
            String correlationId = com.jayway.jsonpath.JsonPath.read(body, "$.correlationId");
            assertFalse(correlationId == null || correlationId.isBlank());
        };
    }

    private static String jsonString(MvcResult result, String path) throws Exception {
        return com.jayway.jsonpath.JsonPath.read(
                result.getResponse().getContentAsString(StandardCharsets.UTF_8), path);
    }

    private static String userToken(Object userId, Object roles, Object type) {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);
        if (type != null) {
            claims.put("type", type);
        }
        return signedToken(claims, true, SIGNING_KEY);
    }

    private static String userToken(Object userId, Object roles, Object type, Key key) {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);
        if (type != null) {
            claims.put("type", type);
        }
        return signedToken(claims, true, key);
    }

    private static String userToken(Object userId, Object roles, Object type, Key key, Instant expiration,
            boolean includeExpiration) {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);
        if (type != null) {
            claims.put("type", type);
        }
        return signedToken(claims, includeExpiration, key, expiration);
    }

    private static String serviceToken() {
        return signedToken(Map.of("type", "SERVICE"), true, SIGNING_KEY,
                Instant.now().plusSeconds(300), "commerce-service");
    }

    private static String signedToken(Map<String, Object> claims, boolean includeExpiration, Key key) {
        return signedToken(claims, includeExpiration, key, Instant.now().plusSeconds(300), "principal");
    }

    private static String signedToken(Map<String, Object> claims, boolean includeExpiration, Key key,
            Instant expiration) {
        return signedToken(claims, includeExpiration, key, expiration, "principal");
    }

    private static String signedToken(Map<String, Object> claims, boolean includeExpiration, Key key,
            Instant expiration, String subject) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Date.from(now.minusSeconds(10)))
                .addClaims(claims);
        if (includeExpiration) {
            builder.setExpiration(Date.from(expiration));
        }
        return builder.signWith(key).compact();
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(SecurityTestController.class)
    static class TestApplication {
    }

    @RestController
    static class SecurityTestController {

        @GetMapping("/api/v1/whoami")
        Map<String, Object> whoami(HttpServletRequest request) {
            String authType = (String) request.getAttribute("authType");
            if ("SERVICE".equals(authType)) {
                return Map.of("authType", authType, "service", request.getAttribute("service"));
            }
            return Map.of("authType", authType,
                    "userId", request.getAttribute("userId"),
                    "roles", request.getAttribute("roles"));
        }

        @GetMapping({ "/api/v1", "/api/v1/protected", "/v1", "/v1/protected" })
        String protectedRoute() {
            return "protected";
        }

        @GetMapping("/internal/v1/protected")
        Map<String, Object> internalRoute(HttpServletRequest request) {
            return Map.of("authType", request.getAttribute("authType"));
        }

        @RequestMapping(path = "/api/v1/public/route", method = { org.springframework.web.bind.annotation.RequestMethod.GET,
                org.springframework.web.bind.annotation.RequestMethod.POST })
        String methodBoundPublicRoute() {
            return "public";
        }

        @PostMapping("/api/v1/auth/login")
        String login() {
            return "login";
        }

        @PostMapping("/api/v1/auth/secret")
        String protectedAuthOperation() {
            return "secret";
        }

        @GetMapping("/openapi/v3/schema")
        String schema() {
            return "schema";
        }

        @GetMapping("/api/v1/role/cashier")
        @RequireRole("CASHIER")
        String cashierRoute() {
            return "cashier";
        }
    }
}
