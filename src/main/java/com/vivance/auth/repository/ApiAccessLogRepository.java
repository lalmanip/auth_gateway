package com.vivance.auth.repository;

import com.vivance.auth.entity.ApiAccessLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ApiAccessLogRepository extends JpaRepository<ApiAccessLog, Long> {
}
