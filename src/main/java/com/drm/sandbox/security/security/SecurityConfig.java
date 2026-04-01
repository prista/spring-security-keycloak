package com.drm.sandbox.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> {
                            authorize
                                    .requestMatchers("/public/test", "/error").permitAll()
                                    .anyRequest().authenticated();
                        }
                )
                .exceptionHandling(handlingConfigurer -> handlingConfigurer
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            accessDeniedException.printStackTrace();
                        }))
                .build();
    }
}
