package com.vivance.auth.client;

import com.vivance.auth.config.VivanceApiProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class VivanceApiClient {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() {};

    private final RestTemplate restTemplate;
    private final VivanceApiProperties props;

    /**
     * Calls the vivance-api domain_currency endpoint and returns the backend session token.
     * Returns null if the call fails so callers can decide whether to surface the error.
     */
    public String fetchSessionToken() {
        try {
            String url = props.getBaseUrl() + "/vivapi-mt/rest/domain_currency";

            Map<String, String> body = Map.of(
                    "domain_key", props.getDomainKey(),
                    "username",   props.getUsername(),
                    "password",   props.getPassword(),
                    "system",     props.getSystem()
            );

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(body), MAP_TYPE);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Object token = response.getBody().get("token");
                if (token instanceof String t) return t;
            }

            log.warn("domain_currency returned unexpected response: {}", response.getStatusCode());
        } catch (Exception e) {
            log.error("Failed to fetch session token from vivance-api: {}", e.getMessage());
        }
        return null;
    }
}
