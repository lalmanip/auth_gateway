package com.vivance.auth.filter;

import com.vivance.auth.entity.ApiAccessLog;
import com.vivance.auth.repository.ApiAccessLogRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class ApiAccessLogFilter extends OncePerRequestFilter {

    public static final String API_ACCESS_LOG_ATTR = "API_ACCESS_LOG_ENTITY";

    private final ApiAccessLogRepository apiAccessLogRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        ApiAccessLog accessLog = new ApiAccessLog();
        accessLog.setModule(extractModule(request.getRequestURI()));
        accessLog.setUrlOrAction(request.getRequestURI());
        accessLog.setIpAddress(request.getRemoteAddr());
        accessLog.setConsumerAppKey(request.getHeader("x-api-key"));
        accessLog.setCreatedDatetime(new Date());

        // Saved synchronously so the generated ID is available to the aspect
        ApiAccessLog saved = apiAccessLogRepository.save(accessLog);
        request.setAttribute(API_ACCESS_LOG_ATTR, saved);

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().contains("/app/auth/");
    }

    // URI example: /vivapi-auth/app/auth/login → split[2] = "app"
    private String extractModule(String uri) {
        String[] parts = uri.split("/");
        return parts.length > 2 ? parts[2] : "auth";
    }
}
