package com.vivance.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Pentest: {@code Cache-Control: no-store} on endpoints that return access/refresh tokens
 * so browsers and intermediate caches never store bearer credentials.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class NoStoreAuthResponseFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        response.setHeader("Cache-Control", "no-store");
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) {
            return true;
        }
        // Context path is /vivapi-auth — match token-issuing user + app auth routes.
        return !(uri.contains("/user/auth/login")
                || uri.contains("/user/auth/register")
                || uri.contains("/user/auth/google")
                || uri.contains("/user/auth/apple")
                || uri.contains("/user/auth/refresh")
                || uri.contains("/app/auth/login")
                || uri.contains("/app/auth/register")
                || uri.contains("/app/auth/refresh")
                || uri.contains("/app/auth/token-info"));
    }
}
