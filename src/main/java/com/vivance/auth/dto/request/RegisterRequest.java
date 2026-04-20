package com.vivance.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class RegisterRequest {
    @NotBlank @Email   private String email;
    @NotBlank @Size(min = 8) private String password;
    @NotBlank          private String firstName;
    @NotBlank          private String lastName;
                       private Integer countryCode;
}
