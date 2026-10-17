package com.transportes.common_security.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import com.transportes.common_security.decorators.RoleAspect;

@AutoConfiguration 
@EnableConfigurationProperties(PublicRoutesProperties.class)
@Import({HeaderAuthInterceptor.class, RoleAspect.class
    ,SecurityConfig.class,WebConfig.class
})
public class CommonSecurityAutoConfiguration {
    
}
