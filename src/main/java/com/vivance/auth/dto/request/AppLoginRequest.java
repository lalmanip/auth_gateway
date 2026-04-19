package com.vivance.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class AppLoginRequest {

    @JsonProperty("domain_key")
    @NotBlank
    private String domainKey;

    @JsonProperty("username")
    @NotBlank
    private String domainUser;

    @JsonProperty("password")
    @NotBlank
    private String domainPassword;

    @JsonProperty("system")
    @NotBlank
    private String environment;
}
