package com.drm.sandbox.security.security;

import com.drm.sandbox.security.AccessTokenJwsStringSerializer;
import com.drm.sandbox.security.JwtAuthenticationConfigurer;
import com.drm.sandbox.security.RefreshTokenJweStringSerializer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.text.ParseException;

@Configuration
public class SecurityConfig {

    @Bean
    public JwtAuthenticationConfigurer jwtAuthenticationConfigurer(
            @Value("${jwt.access-token-key}") String accessTokeKey,
            @Value("${jwt.refresh-token-key}") String refreshTokenKey
    ) throws ParseException, JOSEException {
        return new JwtAuthenticationConfigurer()
                .accessTokenStringSerializer(
                        new AccessTokenJwsStringSerializer(
                                new MACSigner(OctetSequenceKey.parse(accessTokeKey))
                        )
                )
                .refreshTokenStringSerializer(
                        new RefreshTokenJweStringSerializer(
                                new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
                        )
                );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationConfigurer jwtAuthenticationConfigurer
    ) throws Exception {
        http.apply(jwtAuthenticationConfigurer);

        return http
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(c -> c
                        // /error is default view "Whitelabel Error Page"
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/manager.html").hasRole("MANAGER")
                        .anyRequest().authenticated())
                .build();
    }
}
