package com.drm.sandbox.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.Objects;
import java.util.function.Function;

public class JwtAuthenticationConfigurer
        extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenStringSerializer = Objects::toString; // token -> Objects.toString(token)
    private Function<Token, String> accessTokenStringSerializer = Objects::toString; // return (token == null) ? "null" : token.toString();

    public JwtAuthenticationConfigurer refreshTokenStringSerializer(final Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringSerializer(final Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
        return this;
    }

    @Override
    public void init(final HttpSecurity builder) {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            // Disable CSRF protection for the token endpoint, as it is not a browser-based endpoint
            csrfConfigurer.ignoringRequestMatchers(
                    PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/tokens"));
        }
    }

    @Override
    public void configure(final HttpSecurity builder) {
        var filter = new RequestJwsTokensFilter();
        filter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);
        filter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        // Register the filter after ExceptionTranslationFilter,
        // which is responsible for handling authentication exceptions
        // and sending appropriate HTTP responses (e.g., 401 Unauthorized).
        builder.addFilterAfter(filter, ExceptionTranslationFilter.class);
    }
}
