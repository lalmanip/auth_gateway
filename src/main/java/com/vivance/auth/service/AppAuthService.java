package com.vivance.auth.service;

import com.vivance.auth.dto.request.AppLoginRequest;
import com.vivance.auth.dto.request.AppRegisterRequest;
import com.vivance.auth.dto.response.AppAuthResponse;
import com.vivance.auth.entity.ConsumerAccount;
import com.vivance.auth.entity.ConsumerDomain;
import com.vivance.auth.entity.RefreshToken;
import com.vivance.auth.exception.AuthException;
import com.vivance.auth.repository.ConsumerAccountRepository;
import com.vivance.auth.repository.ConsumerDomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppAuthService {

    private final ConsumerAccountRepository accountRepo;
    private final ConsumerDomainRepository domainRepo;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    // Delegating encoder matches {bcrypt}/{pbkdf2}/etc. stored by vivance-api's PasswordUtils
    private final PasswordEncoder appPasswordEncoder = new DelegatingPasswordEncoder(
            "bcrypt", Map.of("bcrypt", new BCryptPasswordEncoder()));

    @Transactional
    public AppAuthResponse register(AppRegisterRequest request) {
        if (domainRepo.existsByDomainKeyAndDomainUserAndEnvironment(
                request.getDomainKey(), request.getDomainUser(), request.getEnvironment())) {
            throw AuthException.conflict("App with these credentials already exists");
        }

        ConsumerAccount account = new ConsumerAccount();
        account.setConsumerName(request.getConsumerName());
        account.setLoginId(request.getDomainUser());
        account.setApiKey(generateApiKey());
        account = accountRepo.save(account);

        ConsumerDomain domain = new ConsumerDomain();
        domain.setConsumerId(account.getConsumerId());
        domain.setDomainKey(request.getDomainKey());
        domain.setDomainUser(request.getDomainUser());
        domain.setDomainPassword(appPasswordEncoder.encode(request.getDomainPassword()));
        domain.setEnvironment(request.getEnvironment());
        domain = domainRepo.save(domain);

        log.info("Registered new app: consumerId={}, domainId={}", account.getConsumerId(), domain.getDomainId());
        return buildResponse(domain, account, true);
    }

    public AppAuthResponse login(AppLoginRequest request) {
        ConsumerDomain domain = domainRepo
                .findByCredential(request.getDomainKey(), request.getDomainUser(), request.getEnvironment(), "Active")
                .orElseThrow(() -> AuthException.unauthorized("Invalid credentials"));

        if (!appPasswordEncoder.matches(request.getDomainPassword(), domain.getDomainPassword())) {
            throw AuthException.unauthorized("Invalid credentials");
        }

        ConsumerAccount account = accountRepo.findById(domain.getConsumerId())
                .orElseThrow(() -> AuthException.unauthorized("Account not found"));

        if (!"Active".equals(account.getStatus())) {
            throw AuthException.unauthorized("Account is inactive");
        }

        return buildResponse(domain, account, false);
    }

    @Transactional
    public AppAuthResponse refresh(String rawRefreshToken) {
        RefreshToken old = refreshTokenService.validateAndRotate(rawRefreshToken);
        String domainId = old.getUserId();
        String newAccessToken = jwtService.generateAccessToken(domainId);
        String newRefreshToken = refreshTokenService.createRefreshToken(domainId);

        return AppAuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(jwtService.getExpiresInSeconds())
                .build();
    }

    @Transactional
    public void logout(String domainId) {
        refreshTokenService.revokeAll(domainId);
        log.info("App logged out, all tokens revoked: domainId={}", domainId);
    }

    // --- helpers ---

    private AppAuthResponse buildResponse(ConsumerDomain domain, ConsumerAccount account, boolean isNew) {
        String domainId = domain.getDomainId().toString();
        String accessToken = jwtService.generateAccessToken(domainId);
        String refreshToken = refreshTokenService.createRefreshToken(domainId);

        return AppAuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getExpiresInSeconds())
                .isNewApp(isNew)
                .build();
    }

    private String generateApiKey() {
        return "viv-" + UUID.randomUUID().toString().replace("-", "");
    }
}
