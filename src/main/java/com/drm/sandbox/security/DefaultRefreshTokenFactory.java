package com.drm.sandbox.security;

import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.UUID;
import java.util.function.Function;

public class DefaultRefreshTokenFactory implements Function<Authentication, Token> {

    @Setter
    private Duration tokenTtl = Duration.ofDays(1);

    // берем на вход basic auth данные
    @Override
    public Token apply(final Authentication authentication) {
        var authorities = new LinkedList<String>();
        authorities.add("JWT_REFRESH");
        authorities.add("JWT_LOGOUT");
        authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> "GRANT_" + authority)
                .forEach(authorities::add);

        var now = Instant.now();
        return new Token(UUID.randomUUID(),
                authentication.getName(),
                authorities,
                now,
                now.plus(this.tokenTtl)
                );
    }
}
