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
    private static final String TRACE_ID_ATTR = "APP_AUTH_TRACE_ID";
    private static final String TRACE_ID_HEADER = "X-Request-Id";

    private final ApiEventLogService apiEventLogService;
    private final ObjectMapper objectMapper;

    @Around("execution(* com.vivance.auth.controller.AppAuthController.*(..))")
    public Object logAppAuth(ProceedingJoinPoint pjp) throws Throwable {
        HttpServletRequest request = resolveRequest();
        String eventName = request != null ? request.getRequestURI() : pjp.getSignature().getName();
        Long accessLogId = resolveAccessLogId(request);
        String traceId = resolveOrCreateTraceId(request);

        String reqHeaders = serializeHeaders(request);
        String reqParams = serializeParams(request);
        String reqBody = serializeRequestBody(pjp.getArgs());

        log.info("APP_AUTH_CALL REQUEST traceId={} accessLogId={} method={} uri={} headers={} params={} body={}",
                traceId,
                accessLogId,
                request != null ? request.getMethod() : null,
                eventName,
                reqHeaders,
                reqParams,
                reqBody);

        apiEventLogService.save(ApiCallEventLog.builder()
                .apiAccessLogId(accessLogId)
                .serviceChannel(SERVICE_CHANNEL)
                .eventName(eventName)
                .eventType("REQUEST")
                .headers(reqHeaders)
                .parameters(reqParams)
                .content(reqBody)
                .build());

        Object result;
        try {
            result = pjp.proceed();
        } catch (Throwable ex) {
            log.info("APP_AUTH_CALL ERROR traceId={} accessLogId={} method={} uri={} error={}",
                    traceId,
                    accessLogId,
                    request != null ? request.getMethod() : null,
                    eventName,
                    ex.getMessage());
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

        String respBody = serializeResponseBody(result);
        Integer status = resolveStatus(result);
        log.info("APP_AUTH_CALL RESPONSE traceId={} accessLogId={} method={} uri={} status={} body={}",
                traceId,
                accessLogId,
                request != null ? request.getMethod() : null,
                eventName,
                status,
                respBody);

        apiEventLogService.save(ApiCallEventLog.builder()
                .apiAccessLogId(accessLogId)
                .serviceChannel(SERVICE_CHANNEL)
                .eventName(eventName)
                .eventType("RESPONSE")
                .content(respBody)
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
            Map<String, Object> params = new LinkedHashMap<>();

            // Caller identity
            params.put("ip", resolveClientIp(request));
            params.put("method", request.getMethod());
            params.put("userAgent", request.getHeader("user-agent"));

            // Query parameters (masked)
            request.getParameterMap().forEach((k, v) -> {
                if (!k.equalsIgnoreCase("password")) {
                    params.put(k, v.length > 0 ? v[0] : "");
                }
            });

            return objectMapper.writeValueAsString(params);
        } catch (Exception e) {
            return null;
        }
    }

    private String resolveClientIp(HttpServletRequest request) {
        // Respect reverse-proxy forwarding headers before falling back to socket address
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
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

    private Integer resolveStatus(Object result) {
        try {
            if (result instanceof ResponseEntity<?> re) {
                return re.getStatusCode().value();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String resolveOrCreateTraceId(HttpServletRequest request) {
        if (request == null) return UUID.randomUUID().toString();

        Object existing = request.getAttribute(TRACE_ID_ATTR);
        if (existing instanceof String s && !s.isBlank()) return s;

        String fromHeader = request.getHeader(TRACE_ID_HEADER);
        String traceId = (fromHeader != null && !fromHeader.isBlank()) ? fromHeader.trim() : UUID.randomUUID().toString();
        request.setAttribute(TRACE_ID_ATTR, traceId);
        return traceId;
    }

    private String stackTraceOf(Throwable ex) {
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
