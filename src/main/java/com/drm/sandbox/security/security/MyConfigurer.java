package com.drm.sandbox.security.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class MyConfigurer extends AbstractHttpConfigurer<MyConfigurer, HttpSecurity> {

    private String realmName = "My realm";

    @Override
    public void init(final HttpSecurity builder) {
        builder.httpBasic(httpBasic -> httpBasic.realmName(this.realmName))
                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests.anyRequest().authenticated());
    }

    @Override
    public void configure(final HttpSecurity builder) {
        super.configure(builder);
    }

    public MyConfigurer realmName(final String realmName) {
        this.realmName = realmName;
        return this;
    }
}
