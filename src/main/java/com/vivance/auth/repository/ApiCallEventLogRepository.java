package com.vivance.auth.repository;

import com.vivance.auth.entity.ApiCallEventLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ApiCallEventLogRepository extends JpaRepository<ApiCallEventLog, Long> {
}
