package com.vivance.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginRequest {
    @JsonProperty("username")
    @NotBlank private String userName;
    @NotBlank private String password;
}
