package com.vivance.auth.logging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vivance.auth.entity.ApiAccessLog;
import com.vivance.auth.entity.ApiCallEventLog;
import com.vivance.auth.filter.ApiAccessLogFilter;
import com.vivance.auth.service.ApiEventLogService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AppAuthLoggingAspect {

    private static final String SERVICE_CHANNEL = "AUTH-APP";
    private static final Set<String> MASKED_HEADERS = Set.of("authorization", "cookie", "x-api-key");
    private static final Set<String> MASKED_BODY_FIELDS = Set.of("password", "domainPassword");

    private final ApiEventLogService apiEventLogService;
    private final ObjectMapper objectMapper;

    @Around("execution(* com.vivance.auth.controller.AppAuthController.*(..))")
    public Object logAppAuth(ProceedingJoinPoint pjp) throws Throwable {
        HttpServletRequest request = resolveRequest();
        String eventName = request != null ? request.getRequestURI() : pjp.getSignature().getName();
        Long accessLogId = resolveAccessLogId(request);

        apiEventLogService.save(ApiCallEventLog.builder()
                .apiAccessLogId(accessLogId)
                .serviceChannel(SERVICE_CHANNEL)
                .eventName(eventName)
                .eventType("REQUEST")
                .headers(serializeHeaders(request))
                .parameters(serializeParams(request))
                .content(serializeRequestBody(pjp.getArgs()))
                .build());

        Object result;
        try {
            result = pjp.proceed();
        } catch (Throwable ex) {
            apiEventLogService.save(ApiCallEventLog.builder()
                    .apiAccessLogId(accessLogId)
                    .serviceChannel(SERVICE_CHANNEL)
                    .eventName(eventName)
                    .eventType("ERROR")
                    .parameters(ex.getMessage())
                    .content(stackTraceOf(ex))
                    .build());
            throw ex;
        }

        apiEventLogService.save(ApiCallEventLog.builder()
                .apiAccessLogId(accessLogId)
                .serviceChannel(SERVICE_CHANNEL)
                .eventName(eventName)
                .eventType("RESPONSE")
                .content(serializeResponseBody(result))
                .build());

        return result;
    }

    private HttpServletRequest resolveRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private Long resolveAccessLogId(HttpServletRequest request) {
        if (request == null) return null;
        ApiAccessLog accessLog = (ApiAccessLog) request.getAttribute(ApiAccessLogFilter.API_ACCESS_LOG_ATTR);
        return accessLog != null ? accessLog.getId() : null;
    }

    private String serializeHeaders(HttpServletRequest request) {
        if (request == null) return null;
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            Enumeration<String> names = request.getHeaderNames();
            if (names != null) {
                while (names.hasMoreElements()) {
                    String name = names.nextElement();
                    if (!MASKED_HEADERS.contains(name.toLowerCase())) {
                        headers.put(name, request.getHeader(name));
                    }
                }
            }
            return objectMapper.writeValueAsString(headers);
        } catch (Exception e) {
            return null;
        }
    }

    private String serializeParams(HttpServletRequest request) {
        if (request == null) return null;
        try {
            Map<String, String> params = new LinkedHashMap<>();
            request.getParameterMap().forEach((k, v) -> {
                if (!k.equalsIgnoreCase("password")) {
                    params.put(k, v.length > 0 ? v[0] : "");
                }
            });
            return params.isEmpty() ? null : objectMapper.writeValueAsString(params);
        } catch (Exception e) {
            return null;
        }
    }

    private String serializeRequestBody(Object[] args) {
        for (Object arg : args) {
            if (arg == null || arg instanceof String) continue;
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = objectMapper.convertValue(arg, Map.class);
                MASKED_BODY_FIELDS.forEach(field -> {
                    if (map.containsKey(field)) map.put(field, "***");
                });
                return objectMapper.writeValueAsString(map);
            } catch (Exception e) {
                log.warn("Could not serialize request body arg: {}", e.getMessage());
            }
        }
        return null;
    }

    private String serializeResponseBody(Object result) {
        try {
            Object body = (result instanceof ResponseEntity<?> re) ? re.getBody() : result;
            return objectMapper.writeValueAsString(body);
        } catch (Exception e) {
            log.warn("Could not serialize response body: {}", e.getMessage());
            return null;
        }
    }

    private String stackTraceOf(Throwable ex) {
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
