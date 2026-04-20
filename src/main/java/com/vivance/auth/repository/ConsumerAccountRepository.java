package com.vivance.auth.repository;

import com.vivance.auth.entity.ConsumerAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ConsumerAccountRepository extends JpaRepository<ConsumerAccount, Long> {

    @Query(value = "SELECT * FROM consumer_account WHERE api_key = ?1", nativeQuery = true)
    Optional<ConsumerAccount> findByApiKey(String apiKey);

    boolean existsByApiKey(String apiKey);
}
