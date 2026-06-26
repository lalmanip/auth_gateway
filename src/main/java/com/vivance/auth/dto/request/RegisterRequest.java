package com.vivance.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class RegisterRequest {
    /** B2C: contact email. B2B: optional when {@link #userName} is set. */
    private String email;
    /** Login id — email or alphanumeric (B2B agents). Falls back to {@link #email} when omitted. */
    private String userName;
    @NotBlank @Size(min = 8) private String password;
    @NotBlank          private String firstName;
    @NotBlank          private String lastName;
    private Integer countryCode;
    /** {@code 3} = B2B agent, {@code 4} = B2C (default). */
    private Integer userType;
    /** {@code 0} = inactive (pending activation), {@code 1} = active (default). */
    private Integer status;
}
