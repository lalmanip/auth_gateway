package com.vivance.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Table(name = "consumer_account")
@Getter @Setter @NoArgsConstructor
public class ConsumerAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "consumer_id")
    private Long consumerId;

    @Column(name = "consumer_name")
    private String consumerName;

    @Column(name = "login_id")
    private String loginId;

    @Column(name = "api_key", unique = true)
    private String apiKey;

    @Column(name = "email")
    private String email;

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
