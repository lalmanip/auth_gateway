package com.vivance.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Table(name = "consumer_domain")
@Getter @Setter @NoArgsConstructor
public class ConsumerDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "domain_id")
    private Long domainId;

    @Column(name = "consumer_id", nullable = false)
    private Long consumerId;

    @Column(name = "domain_key")
    private String domainKey;

    @Column(name = "domain_user")
    private String domainUser;

    @Column(name = "domain_password")
    private String domainPassword;

    @Column(name = "environment")
    private String environment;

    @Column(name = "status")
    private String status = "Active";

    @Column(name = "created_at", updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt;

    @Column(name = "updated_at")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updatedAt;

    @PrePersist
    void onCreate() {
        createdAt = updatedAt = new Date();
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = new Date();
    }
}
