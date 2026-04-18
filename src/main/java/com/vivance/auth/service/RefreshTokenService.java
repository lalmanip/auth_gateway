package com.vivance.auth.service;

import com.vivance.auth.entity.RefreshToken;
import com.vivance.auth.exception.AuthException;
import com.vivance.auth.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final long expiryDays;

    public RefreshTokenService(
            RefreshTokenRepository repo,
            @Value("${auth.jwt.refresh-token-expiry-days}") long expiryDays) {
        this.repo = repo;
        this.expiryDays = expiryDays;
    }

    public String createRefreshToken(String userId) {
        String rawToken = UUID.randomUUID().toString() + UUID.randomUUID().toString();

        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setTokenHash(hash(rawToken));
        token.setExpiresAt(LocalDateTime.now().plusDays(expiryDays));
        repo.save(token);

        return rawToken;
    }

    @Transactional
    public RefreshToken validateAndRotate(String rawToken) {
        String tokenHash = hash(rawToken);
        RefreshToken stored = repo.findByTokenHash(tokenHash)
                .orElseThrow(() -> AuthException.unauthorized("Invalid refresh token"));

        if (stored.isRevoked()) throw AuthException.unauthorized("Refresh token has been revoked");
        if (stored.isExpired()) throw AuthException.unauthorized("Refresh token has expired");

        stored.setRevoked(true);
        repo.save(stored);

        return stored;
    }

    @Transactional
    public void revokeAll(String userId) {
        repo.revokeAllByUserId(userId);
    }

    public String hash(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
