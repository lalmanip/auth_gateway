package com.vivance.auth.entity;

import com.vivance.auth.crypto.AesAttributeConverter;
import jakarta.persistence.*;
import jakarta.persistence.Convert;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user")
@Getter @Setter @NoArgsConstructor
public class User {

    /** B2C end-user type — same default as vivapi-user {@code /user/create}. */
    public static final int DEFAULT_USER_TYPE = 4;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "uuid", nullable = false, unique = true, length = 36)
    private String userId;

    @Convert(converter = AesAttributeConverter.class)
    @Column(unique = true)
    private String email;

    @Convert(converter = AesAttributeConverter.class)
    @Column(name = "user_name")
    private String userName;

    @Column(name = "user_type")
    private int userType = DEFAULT_USER_TYPE;

    @Column(name = "first_name", length = 100)
    private String firstName;

    @Column(name = "last_name", length = 100)
    private String lastName;

    @Column(name = "password")
    private String passwordHash;

    @Column(name = "country_code")
    private Integer countryCode;

    @Convert(converter = StatusConverter.class)
    @Column(nullable = false)
    private Status status = Status.ACTIVE;

    @Column(name = "created_on", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "modified_on")
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        if (userId == null) userId = UUID.randomUUID().toString();
        createdAt = updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum Status { ACTIVE, INACTIVE }
}
