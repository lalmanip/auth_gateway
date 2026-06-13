package com.vivance.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Table(name = "api_access_log")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiAccessLog {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "module")
    private String module;

    @Column(name = "user_session_id")
    private String userSessionId;

    @Column(name = "consumer_app_key")
    private String consumerAppKey;

    @Column(name = "consumer_domain_key")
    private String consumerDomainKey;

    @Column(name = "url_or_action")
    private String urlOrAction;

    @Column(name = "result_token")
    private String resultToken;

    @Column(name = "app_payment_refid")
    private String appPaymentRefId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "created_datetime")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdDatetime;
}
