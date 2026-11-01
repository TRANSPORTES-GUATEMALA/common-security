package com.transportes.common_security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.beans.factory.annotation.Autowired;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Autowired
    private PublicRoutesProperties publicRoutes;

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> {
                    // La cadena deja pasar estos prefijos para que el interceptor valide el JWT
                    authorize.requestMatchers("/api/v1/**", "/v1/**", "/internal/v1/**").permitAll();
                    publicRoutes.validRules().forEach(rule ->
                            authorize.requestMatchers(rule.method(), rule.path()).permitAll());
                    authorize.anyRequest().denyAll();
                });
        return http.build();
    }
}
