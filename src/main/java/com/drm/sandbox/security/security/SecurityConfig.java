package com.drm.sandbox.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(c -> c
                        // /error is default view "Whitelabel Error Page"
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .apply(new HexConfigurer());
        return http
                .build();
    }
}
