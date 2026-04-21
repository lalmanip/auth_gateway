-- Auth service schema
-- Run once against the vivance_auth database

CREATE DATABASE IF NOT EXISTS vivance_auth
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE vivance_auth;

-- End-user identity
CREATE TABLE IF NOT EXISTS users (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id      VARCHAR(36)  NOT NULL UNIQUE,          -- UUID, shared with business services
    email        VARCHAR(255) UNIQUE,
    first_name   VARCHAR(100),
    last_name    VARCHAR(100),
    password_hash VARCHAR(255),                          -- NULL for social-only accounts
    country_code VARCHAR(10),
    status       ENUM('ACTIVE','INACTIVE') NOT NULL DEFAULT 'ACTIVE',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Social login links (Google / Apple)
CREATE TABLE IF NOT EXISTS user_auth_providers (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id      VARCHAR(36)  NOT NULL,
    provider     ENUM('GOOGLE','APPLE') NOT NULL,
    provider_uid VARCHAR(255) NOT NULL,                  -- Google sub / Apple sub
    email        VARCHAR(255),
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_provider_uid (provider, provider_uid),
    CONSTRAINT fk_uap_user FOREIGN KEY (user_id) REFERENCES users (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Refresh token store (only hash is persisted, never the raw token)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(36)  NOT NULL,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  DATETIME     NOT NULL,
    revoked     TINYINT(1)   NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_rt_user_id ON refresh_tokens (user_id);

-- API access log parent record (one row per inbound request; mirrors vivance_api.api_access_log)
CREATE TABLE IF NOT EXISTS api_access_log (
    id                BIGINT AUTO_INCREMENT PRIMARY KEY,
    module            VARCHAR(100),
    user_session_id   VARCHAR(255),
    consumer_app_key  VARCHAR(255),
    consumer_domain_key VARCHAR(255),
    url_or_action     VARCHAR(500),
    result_token      VARCHAR(500),
    app_payment_refid VARCHAR(255),
    ip_address        VARCHAR(50),
    created_datetime  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- API call audit log (mirrors vivance_api.api_call_event_log)
CREATE TABLE IF NOT EXISTS api_call_event_log (
    id                BIGINT AUTO_INCREMENT PRIMARY KEY,
    api_access_log_id BIGINT NULL,
    service_channel   VARCHAR(100),
    event_name        VARCHAR(500),
    event_type        VARCHAR(50),
    headers           TEXT,
    parameters        TEXT,
    result_token      VARCHAR(500),
    app_payment_refid VARCHAR(255),
    content           TEXT,
    created_datetime  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_acel_event_type ON api_call_event_log (event_type);
CREATE INDEX idx_acel_event_name ON api_call_event_log (event_name(255));
