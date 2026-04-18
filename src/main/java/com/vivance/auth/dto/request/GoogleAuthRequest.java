package com.vivance.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class GoogleAuthRequest {
    @NotBlank private String idToken;
}
