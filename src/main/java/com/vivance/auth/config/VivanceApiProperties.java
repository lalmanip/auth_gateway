package com.vivance.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "vivance.api")
public class VivanceApiProperties {
    private String baseUrl;
    private String domainKey;
    private String username;
    private String password;
    private String system;
}
