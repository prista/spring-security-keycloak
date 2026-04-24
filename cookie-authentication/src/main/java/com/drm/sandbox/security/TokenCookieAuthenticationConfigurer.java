package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import lombok.Setter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;

import java.util.function.Function;

public class TokenCookieAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {

    private Function<Authentication, Token> tokenCookieFactory;
    private Function<Token, String> tokenStringSerializer;

    public TokenCookieAuthenticationConfigurer tokenCookieFactory(
            Function<Authentication, Token> tokenCookieFactory) {
        this.tokenCookieFactory = tokenCookieFactory;
        return this;
    }

    public TokenCookieAuthenticationConfigurer tokenStringSerializer(
            Function<Token, String> tokenStringSerializer) {
        this.tokenStringSerializer = tokenStringSerializer;
        return this;
    }

    @Override
    public void init(HttpSecurity builder) {
        var strategy = new TokenCookieSessionAuthenticationStrategy();
        if (tokenCookieFactory != null) {
            strategy.setTokenCookieFactory(tokenCookieFactory);
        }
        if (tokenStringSerializer != null) {
            strategy.setTokenStringSerializer(tokenStringSerializer);
        }

        // Подключаем стратегию к SessionManagementConfigurer.
        // SessionManagementFilter вызовет её после успешной аутентификации
        // (HTTP Basic, form login — любой фильтр, что укладывает Authentication в контекст).
        builder.sessionManagement(s -> s.sessionAuthenticationStrategy(strategy));
    }

    @Override
    public void configure(HttpSecurity builder) {
        super.configure(builder);
    }
}
