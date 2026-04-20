package com.vivance.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppAuthResponse {
    @JsonProperty("Token")
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private Boolean isNewApp;
}
