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
