package com.transportes.common_security.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import com.transportes.common_security.decorators.RoleAspect;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(PublicRoutesProperties.class)
@EnableAspectJAutoProxy(proxyTargetClass = true)
@Import({ HeaderAuthInterceptor.class, RoleAspect.class, SecurityConfig.class, WebConfig.class,
        SecurityAuthorizationExceptionHandler.class })
public class CommonSecurityAutoConfiguration {
}
