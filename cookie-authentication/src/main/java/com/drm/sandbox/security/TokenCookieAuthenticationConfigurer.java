package com.drm.sandbox.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class TokenCookieAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {


    @Override
    public void init(HttpSecurity builder) {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) {
        super.configure(builder);
    }
}
