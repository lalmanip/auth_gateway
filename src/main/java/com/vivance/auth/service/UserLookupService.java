package com.vivance.auth.service;

import com.vivance.auth.crypto.AesEncryptionService;
import com.vivance.auth.entity.User;
import com.vivance.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Resolves users by login id (email or username) against both AES-encrypted
 * and legacy plaintext values stored in the shared {@code user} table.
 */
@Service
@RequiredArgsConstructor
public class UserLookupService {

    private final UserRepository userRepository;
    private final AesEncryptionService aesEncryptionService;

    public boolean loginIdExists(String loginId) {
        LookupValues values = toLookupValues(loginId);
        return userRepository.countByEmailOrUserNameValues(values.encrypted(), values.plain()) > 0;
    }

    public Optional<User> findByLoginId(String loginId) {
        LookupValues values = toLookupValues(loginId);
        return userRepository.findFirstByEmailOrUserNameValues(values.encrypted(), values.plain());
    }

    private LookupValues toLookupValues(String loginId) {
        String plain = loginId.trim();
        return new LookupValues(aesEncryptionService.encrypt(plain), plain);
    }

    private record LookupValues(String encrypted, String plain) {}
}
