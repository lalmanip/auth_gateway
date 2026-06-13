package com.vivance.auth.service;

import com.vivance.auth.entity.ApiCallEventLog;
import com.vivance.auth.repository.ApiCallEventLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class ApiEventLogService {

    private final ApiCallEventLogRepository repository;

    @Async
    public void save(ApiCallEventLog entry) {
        try {
            if (entry.getCreatedDatetime() == null) {
                entry.setCreatedDatetime(new Date());
            }
            repository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to persist api_call_event_log: {}", e.getMessage());
        }
    }
}
