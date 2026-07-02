package com.vivance.auth.service;

import com.vivance.auth.client.VivanceApiClient;
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
    private final VivanceApiClient vivanceApiClient;

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
            throw AuthException.conflict("Email is already registered");
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
        String sessionToken = vivanceApiClient.fetchSessionToken();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .expiresIn(jwtService.getExpiresInSeconds())
                .userId(userId)
                .isNewUser(isNew)
                .sessionToken(sessionToken)
                .build();
    }
}
