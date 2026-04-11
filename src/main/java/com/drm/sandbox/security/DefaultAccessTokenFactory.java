package com.drm.sandbox.security;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

public class DefaultAccessTokenFactory implements Function<Token, Token> {

    private Duration tokenTtl = Duration.ofMinutes(5);

    public void setTokenTtl(final Duration tokenTtl) {
        this.tokenTtl = tokenTtl;
    }

    @Override
    public Token apply(final Token refreshToken) {
        var now = Instant.now();
        return new Token(
                refreshToken.id(), // the same as refresh token
                refreshToken.subject(), // the same as refresh token
                refreshToken.authorities()
                        .stream()
                        .filter(authority -> authority.startsWith("GRANT_"))
                        .map(authority -> authority.replace("GRANT_", ""))
                        .toList(),
                now,
                now.plus(this.tokenTtl)
        );
    }
}
