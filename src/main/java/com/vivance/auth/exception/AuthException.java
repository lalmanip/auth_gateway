package com.vivance.auth.exception;

import org.springframework.http.HttpStatus;

public class AuthException extends RuntimeException {

    private final HttpStatus status;

    public AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public static AuthException unauthorized(String message) {
        return new AuthException(message, HttpStatus.UNAUTHORIZED);
    }

    public static AuthException conflict(String message) {
        return new AuthException(message, HttpStatus.CONFLICT);
    }

    public static AuthException badRequest(String message) {
        return new AuthException(message, HttpStatus.BAD_REQUEST);
    }
}
