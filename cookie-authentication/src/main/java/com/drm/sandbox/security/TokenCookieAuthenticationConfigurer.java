package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import com.drm.sandbox.TokenAuthenticationUserDetailsService;
import com.drm.sandbox.TokenUser;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;

import java.util.Date;
import java.util.function.Function;

public class TokenCookieAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {

    private Function<String, Token> tokenStringDeserializer;
    private JdbcTemplate jdbcTemplate;

    @Override
    public void init(HttpSecurity builder) {
        builder.logout(logout -> logout.addLogoutHandler(
                        new CookieClearingLogoutHandler("__Host-auth-token"))
                .addLogoutHandler((request, response, authentication) -> {
                    if (authentication != null &&
                            authentication.getPrincipal() instanceof TokenUser user) {
                        this.jdbcTemplate.update("insert into t_deactivated_token (id, c_keep_until) values (?, ?)",
                                user.getToken().id(), Date.from(user.getToken().expiresAt()));

                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                    }
                }));
    }

    @Override
    public void configure(HttpSecurity builder) {
        var cookieAuthFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new TokenCookieAuthenticationConverter(this.tokenStringDeserializer));
        // This filter is transversal.
        // After successful authentication, request processing should continue,
        // so the successHandler will be empty.
        cookieAuthFilter.setSuccessHandler((request,
                                            response,
                                            authentication) -> {
        });
        cookieAuthFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(
                        new Http403ForbiddenEntryPoint()
                )
        );

        var authProvider = new PreAuthenticatedAuthenticationProvider();
        authProvider.setPreAuthenticatedUserDetailsService(
                new TokenAuthenticationUserDetailsService(this.jdbcTemplate)
        );

        builder.addFilterAfter(cookieAuthFilter, CsrfFilter.class)
                .authenticationProvider(authProvider);
    }

    public TokenCookieAuthenticationConfigurer tokenStringDeserializer(
            final Function<String, Token> tokenStringDeserializer) {
        this.tokenStringDeserializer = tokenStringDeserializer;
        return this;
    }

    public TokenCookieAuthenticationConfigurer jdbcTemplate(final JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        return this;
    }
}
