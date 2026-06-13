package com.vivance.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class VivanceAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(VivanceAuthApplication.class, args);
         System.out.println("====== Auth Gateway Started  =======");
    }
}
