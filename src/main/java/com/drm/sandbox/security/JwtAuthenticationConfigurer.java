package com.drm.sandbox.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.Objects;
import java.util.function.Function;

public class JwtAuthenticationConfigurer
        extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenStringSerializer = Objects::toString; // token -> Objects.toString(token)
    private Function<Token, String> accessTokenStringSerializer = Objects::toString; // return (token == null) ? "null" : token.toString();
    private Function<String, Token> accessTokenStringDeserializer;
    private Function<String, Token> refreshTokenStringDeserializer;

    public JwtAuthenticationConfigurer refreshTokenStringSerializer(final Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringSerializer(final Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringDeserializer(Function<String, Token> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        return this;
    }

    public JwtAuthenticationConfigurer refreshTokenStringDeserializer(Function<String, Token> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
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
        var requestJwtTokensFilter = new RequestJwsTokensFilter();
        requestJwtTokensFilter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);
        requestJwtTokensFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        // Register the filter after ExceptionTranslationFilter,
        // which is responsible for handling authentication exceptions
        // and sending appropriate HTTP responses (e.g., 401 Unauthorized).

        var jwtAuthenticationFilter =
                new AuthenticationFilter(
                        builder.getSharedObject(AuthenticationManager.class),
                        new JwtAuthenticationConverter(
                                this.accessTokenStringDeserializer,
                                this.refreshTokenStringDeserializer)
                );
        jwtAuthenticationFilter.setSuccessHandler((request, response, authentication) ->
                CsrfFilter.skipRequest(request));
        jwtAuthenticationFilter.setFailureHandler((request, response, exception) ->
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or expired token"));

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(new TokenAuthenticationUserDetailsService());

        var refreshTokenFilter = new RefreshTokenFilter();

        builder.addFilterAfter(requestJwtTokensFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, CsrfFilter.class)
                .addFilterBefore(refreshTokenFilter, ExceptionTranslationFilter.class)
                .authenticationProvider(authenticationProvider);
    }
}
