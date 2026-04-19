package com.vivance.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class AppRegisterRequest {

    @NotBlank
    private String consumerName;

    @NotBlank
    private String domainKey;

    @NotBlank
    private String domainUser;

    @NotBlank
    private String domainPassword;

    @NotBlank
    private String environment;
}
