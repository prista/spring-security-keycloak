package com.drm.sandbox.security;

import lombok.Setter;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

public class DefaultAccessTokenFactory implements Function<Token, Token> {

    @Setter
    private Duration tokenTtl = Duration.ofMinutes(5);

    @Override
    public Token apply(final Token refreshToken) {
        var now = Instant.now();
        return new Token(
                refreshToken.id(),      // the same as refresh token
                refreshToken.subject(), // the same as refresh token
                // since we take refreshToken, which contains renamed (SS) grants,
                // need to rename them back (GRANT_ROLE_MANAGER -> ROLE_MANAGER)
                refreshToken.authorities()
                        .stream()
                        .filter(authority -> authority.startsWith("GRANT_")) // need to rename
                        .map(authority -> authority.replace("GRANT_", ""))
                        .toList(),
                now,
                now.plus(this.tokenTtl)
        );
    }
}
