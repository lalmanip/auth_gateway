package com.vivance.auth.repository;

import com.vivance.auth.entity.ConsumerDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ConsumerDomainRepository extends JpaRepository<ConsumerDomain, Long> {

    @Query(value = "SELECT * FROM consumer_domain WHERE domain_key = ?1 AND domain_user = ?2 AND environment = ?3 AND status = ?4 LIMIT 1",
           nativeQuery = true)
    Optional<ConsumerDomain> findByCredential(String domainKey, String domainUser, String environment, String status);

    boolean existsByDomainKeyAndDomainUserAndEnvironment(String domainKey, String domainUser, String environment);
}
