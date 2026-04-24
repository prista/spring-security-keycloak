package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

public class TokenCookieFactory
        implements Function<Authentication, Token> {

    @Setter
    private Duration tokenTtl = Duration.ofDays(1);

    @Override
    public Token apply(Authentication authentication) {
        var now = Instant.now();

        return new Token(
                UUID.randomUUID(),
                authentication.getName(),
                authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(),
                now,
                now.plus(this.tokenTtl)
        );
    }
}
