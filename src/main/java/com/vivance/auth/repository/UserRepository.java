package com.vivance.auth.repository;

import com.vivance.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserId(String userId);

    /** Native count — avoids hydrating entities and running attribute converters. */
    @Query(value = """
            SELECT COUNT(*) FROM user
            WHERE email IN (:encrypted, :plain) OR user_name IN (:encrypted, :plain)
            """, nativeQuery = true)
    long countByEmailOrUserNameValues(@Param("encrypted") String encrypted, @Param("plain") String plain);

    @Query(value = """
            SELECT * FROM user
            WHERE email IN (:encrypted, :plain) OR user_name IN (:encrypted, :plain)
            LIMIT 1
            """, nativeQuery = true)
    Optional<User> findFirstByEmailOrUserNameValues(@Param("encrypted") String encrypted, @Param("plain") String plain);
}
