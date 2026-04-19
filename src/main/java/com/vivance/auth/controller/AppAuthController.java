package com.vivance.auth.controller;

import com.vivance.auth.dto.request.AppLoginRequest;
import com.vivance.auth.dto.request.AppRegisterRequest;
import com.vivance.auth.dto.request.RefreshTokenRequest;
import com.vivance.auth.dto.response.AppAuthResponse;
import com.vivance.auth.exception.AuthException;
import com.vivance.auth.service.AppAuthService;
import com.vivance.auth.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/app/auth")
@RequiredArgsConstructor
@Tag(name = "App Authentication")
public class AppAuthController {

    private final AppAuthService appAuthService;
    private final JwtService jwtService;

    @PostMapping("/register")
    @Operation(summary = "Register a new application (creates consumer_account + consumer_domain)")
    public ResponseEntity<AppAuthResponse> register(@Valid @RequestBody AppRegisterRequest request) {
        return ResponseEntity.ok(appAuthService.register(request));
    }

    @PostMapping("/login")
    @Operation(summary = "App login using domain credentials")
    public ResponseEntity<AppAuthResponse> login(@Valid @RequestBody AppLoginRequest request) {
        return ResponseEntity.ok(appAuthService.login(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh app access token")
    public ResponseEntity<AppAuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(appAuthService.refresh(request.getRefreshToken()));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout app — revokes all refresh tokens", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        String token = extractBearerToken(authHeader);
        if (!jwtService.isValid(token)) throw AuthException.unauthorized("Invalid token");
        String domainId = jwtService.extractUserId(token);
        appAuthService.logout(domainId);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    private String extractBearerToken(String header) {
        if (header == null || !header.startsWith("Bearer "))
            throw AuthException.unauthorized("Missing or malformed Authorization header");
        return header.substring(7);
    }
}
