package com.vivance.auth.repository;

import com.vivance.auth.entity.UserAuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserAuthProviderRepository extends JpaRepository<UserAuthProvider, Long> {
    Optional<UserAuthProvider> findByProviderAndProviderUid(UserAuthProvider.Provider provider, String providerUid);
}
