package com.vivance.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class AppleAuthRequest {
    @NotBlank private String identityToken;
}
