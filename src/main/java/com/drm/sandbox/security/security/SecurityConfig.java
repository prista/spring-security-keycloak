package com.drm.sandbox.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> {
                            authorize.requestMatchers("/public/**").permitAll();
                            authorize.anyRequest().authenticated();
                        }
                )
                .formLogin(form -> form
                        .loginPage("/public/sign-in.html")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/api/v1/greetings")
                        .permitAll()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((request,
                                                   response,
                                                   authException) ->
                                response.sendRedirect("/public/sign-in.html"))
                )
                .build();
    }
}
