package com.vivance.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Table(name = "api_call_event_log")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiCallEventLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "api_access_log_id")
    private Long apiAccessLogId;

    @Column(name = "service_channel")
    private String serviceChannel;

    @Column(name = "event_name")
    private String eventName;

    @Column(name = "event_type")
    private String eventType;

    @Column(name = "headers", columnDefinition = "TEXT")
    private String headers;

    @Column(name = "parameters", columnDefinition = "TEXT")
    private String parameters;

    @Column(name = "result_token")
    private String resultToken;

    @Column(name = "app_payment_refid")
    private String appPaymentRefId;

    @Column(name = "content", columnDefinition = "TEXT")
    private String content;

    @Column(name = "created_datetime")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdDatetime;
}
