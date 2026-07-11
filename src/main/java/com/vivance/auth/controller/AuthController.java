package com.vivance.auth.controller;

import com.vivance.auth.dto.request.*;
import com.vivance.auth.dto.response.AuthResponse;
import com.vivance.auth.exception.AuthException;
import com.vivance.auth.service.AuthService;
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
@RequestMapping("/user/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/login")
    @Operation(summary = "Email / password login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/register")
    @Operation(summary = "Email registration")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/google")
    @Operation(summary = "Google Sign-In")
    public ResponseEntity<AuthResponse> googleSignIn(@Valid @RequestBody GoogleAuthRequest request) {
        return ResponseEntity.ok(authService.googleSignIn(request));
    }

    @PostMapping("/apple")
    @Operation(summary = "Apple Sign-In")
    public ResponseEntity<AuthResponse> appleSignIn(@Valid @RequestBody AppleAuthRequest request) {
        return ResponseEntity.ok(authService.appleSignIn(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout — revokes all refresh tokens", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader("Authorization") String authHeader) {
        String token = extractBearerToken(authHeader);
        if (!jwtService.isValid(token)) throw AuthException.unauthorized("Invalid token");
        String userId = jwtService.extractUserId(token);
        authService.logout(userId);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @PostMapping("/change-password")
    @Operation(
            summary = "Change password (authenticated)",
            description = "Requires Bearer access token. Stores BCrypt hash compatible with /login.",
            security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Map<String, String>> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody ChangePasswordRequest request) {
        String token = extractBearerToken(authHeader);
        if (!jwtService.isValid(token)) throw AuthException.unauthorized("Invalid token");
        String userId = jwtService.extractUserId(token);
        authService.changePassword(userId, request);
        return ResponseEntity.ok(Map.of(
                "message", "Password changed successfully. Please sign in again."));
    }

    @PostMapping("/reset-password")
    @Operation(
            summary = "Reset password with forgot-password token",
            description = "Use token from forgot-password email. Stores BCrypt hash compatible with /login.")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(Map.of("message", "Password reset successfully. Please sign in."));
    }

    private String extractBearerToken(String header) {
        if (header == null || !header.startsWith("Bearer "))
            throw AuthException.unauthorized("Missing or malformed Authorization header");
        return header.substring(7);
    }
}
