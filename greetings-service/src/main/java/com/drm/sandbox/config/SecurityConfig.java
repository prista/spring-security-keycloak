package com.drm.sandbox.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(configurer -> configurer.anyRequest().authenticated())
                .sessionManagement(configurer ->
                        configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable) // because stateless JWT authentication
                .oauth2ResourceServer(configurer ->
                        configurer.jwt(jwt -> {
                            // translates the parsed JWT into Authentication object
                            var jwtAuthenticationConverter = new JwtAuthenticationConverter();
                            // which claim from the JWT should be used as the Principal's name. (instead of UUID or the like)
                            jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");
                            jwt.jwtAuthenticationConverter(jwtAuthenticationConverter);
                        }))
                .build();
    }

}
