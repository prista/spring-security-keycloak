package com.drm.sandbox.security.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


public class HexConfigurer extends AbstractHttpConfigurer<HexConfigurer, HttpSecurity> {

    private AuthenticationEntryPoint authenticationEntryPoint =
            ((request, response, authException) -> {
                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Hex");
                response.sendError(HttpStatus.UNAUTHORIZED.value());
            });
    @Override
    public void init(final HttpSecurity builder) {
        builder.exceptionHandling(c ->
                c.authenticationEntryPoint(authenticationEntryPoint));
    }

    @Override
    public void configure(final HttpSecurity builder) {
        final var authManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilterBefore(new HexAuthenticationFilter(authManager, this.authenticationEntryPoint),
                BasicAuthenticationFilter.class);
    }

    public HexConfigurer authenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }
}
