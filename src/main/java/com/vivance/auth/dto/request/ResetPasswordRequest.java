package com.vivance.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class ResetPasswordRequest {
    /** Token from forgot-password email ({@code user.pwd_token}). */
    @NotBlank
    private String token;

    @NotBlank
    @Size(min = 8)
    private String newPassword;
}
