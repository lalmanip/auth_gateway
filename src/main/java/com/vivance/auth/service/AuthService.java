package com.vivance.auth.service;

import com.vivance.auth.dto.request.*;
import com.vivance.auth.dto.response.AuthResponse;
import com.vivance.auth.entity.RefreshToken;
import com.vivance.auth.entity.User;
import com.vivance.auth.entity.UserAuthProvider;
import com.vivance.auth.exception.AuthException;
import com.vivance.auth.repository.UserAuthProviderRepository;
import com.vivance.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserLookupService userLookupService;
    private final UserAuthProviderRepository providerRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final SocialAuthService socialAuthService;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String loginId = request.getUserName().trim();
        User user = userLookupService.findByLoginId(loginId)
                .orElseThrow(() -> AuthException.unauthorized("Invalid credentials"));

        if (user.getPasswordHash() == null)
            throw AuthException.unauthorized("This account uses social login");

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
            throw AuthException.unauthorized("Invalid credentials");

        if (user.getStatus() == User.Status.INACTIVE)
            throw AuthException.unauthorized("Account is inactive");

        return buildTokenResponse(user.getUserId(), false);
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String loginId = resolveLoginId(request);

        if (userLookupService.loginIdExists(loginId)) {
            throw AuthException.conflict(
                    "An account with this email already exists. Try Sign In or use Forgot Password.");
        }

        int userType = request.getUserType() != null
                ? request.getUserType()
                : User.DEFAULT_USER_TYPE;
        User.Status status = request.getStatus() != null && request.getStatus() == 0
                ? User.Status.INACTIVE
                : User.Status.ACTIVE;

        User user = new User();
        user.setEmail(loginId);
        user.setUserName(loginId);
        user.setUserType(userType);
        user.setStatus(status);
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setCountryCode(request.getCountryCode());
        userRepository.save(user);

        log.info("New user registered: uuid={}, userType={}, status={}",
                user.getUserId(), user.getUserType(), user.getStatus());
        return buildTokenResponse(user.getUserId(), true);
    }

    private static String resolveLoginId(RegisterRequest request) {
        if (request.getUserName() != null && !request.getUserName().isBlank()) {
            return request.getUserName().trim();
        }
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            return request.getEmail().trim();
        }
        throw AuthException.badRequest("email or userName is required");
    }

    @Transactional
    public AuthResponse googleSignIn(GoogleAuthRequest request) {
        SocialAuthService.SocialUserInfo info = socialAuthService.verifyGoogle(request.getIdToken());
        return handleSocialLogin(info, UserAuthProvider.Provider.GOOGLE);
    }

    @Transactional
    public AuthResponse appleSignIn(AppleAuthRequest request) {
        SocialAuthService.SocialUserInfo info = socialAuthService.verifyApple(request.getIdentityToken());
        return handleSocialLogin(info, UserAuthProvider.Provider.APPLE);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        RefreshToken old = refreshTokenService.validateAndRotate(request.getRefreshToken());
        String newAccessToken = jwtService.generateAccessToken(old.getUserId());
        String newRefreshToken = refreshTokenService.createRefreshToken(old.getUserId());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(jwtService.getExpiresInSeconds())
                .build();
    }

    @Transactional
    public void logout(String userId) {
        refreshTokenService.revokeAll(userId);
        log.info("User logged out, all tokens revoked: {}", userId);
    }

    /**
     * Authenticated password change — stores BCrypt hash (same as register/login).
     * Revokes all refresh tokens so existing sessions must re-login.
     */
    @Transactional
    public void changePassword(String userId, ChangePasswordRequest request) {
        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> AuthException.unauthorized("Invalid token"));

        if (user.getPasswordHash() == null) {
            throw AuthException.badRequest("This account uses social login and has no password");
        }
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw AuthException.unauthorized("Current password is incorrect");
        }
        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            throw AuthException.badRequest("New password must be different from current password");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPwdToken(null);
        user.setPwdTokenExpiry(null);
        userRepository.save(user);
        refreshTokenService.revokeAll(userId);
        log.info("Password changed for user uuid={}", userId);
    }

    /**
     * Forgot-password completion — token from {@code /vivapi-user/user/forgotpasswd} email.
     * Stores BCrypt hash (same as register/login).
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByPwdToken(request.getToken())
                .orElseThrow(() -> AuthException.badRequest("Invalid or expired token"));

        if (user.getPwdTokenExpiry() == null
                || user.getPwdTokenExpiry().isBefore(LocalDateTime.now())) {
            throw AuthException.badRequest("Invalid or expired token");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPwdToken(null);
        user.setPwdTokenExpiry(null);
        userRepository.save(user);
        refreshTokenService.revokeAll(user.getUserId());
        log.info("Password reset via token for user uuid={}", user.getUserId());
    }

    // --- helpers ---

    private AuthResponse handleSocialLogin(SocialAuthService.SocialUserInfo info,
                                           UserAuthProvider.Provider provider) {
        boolean isNew = false;

        UserAuthProvider existing = providerRepository
                .findByProviderAndProviderUid(provider, info.providerUid())
                .orElse(null);

        User user;
        if (existing != null) {
            user = userRepository.findByUserId(existing.getUserId())
                    .orElseThrow(() -> new IllegalStateException("Orphaned provider link"));
        } else {
            // Link to existing email account if one exists, else create new user
            user = userLookupService.findByLoginId(info.email()).orElse(null);
            if (user == null) {
                user = new User();
                user.setEmail(info.email());
                user.setUserName(info.email());
                user.setUserType(User.DEFAULT_USER_TYPE);
                userRepository.save(user);
                isNew = true;
            }

            UserAuthProvider link = new UserAuthProvider();
            link.setUserId(user.getUserId());
            link.setProvider(provider);
            link.setProviderUid(info.providerUid());
            link.setEmail(info.email());
            providerRepository.save(link);

            log.info("Linked {} provider to user: {}", provider, user.getUserId());
        }

        if (user.getStatus() == User.Status.INACTIVE)
            throw AuthException.unauthorized("Account is inactive");

        return buildTokenResponse(user.getUserId(), isNew);
    }

    private AuthResponse buildTokenResponse(String userId, boolean isNew) {
        String accessToken = jwtService.generateAccessToken(userId);
        String rawRefreshToken = refreshTokenService.createRefreshToken(userId);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .expiresIn(jwtService.getExpiresInSeconds())
                .userId(userId)
                .isNewUser(isNew)
                .build();
    }
}
