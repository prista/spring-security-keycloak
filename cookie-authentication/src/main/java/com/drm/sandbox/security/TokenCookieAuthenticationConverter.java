package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Function;
import java.util.stream.Stream;

@RequiredArgsConstructor
public class TokenCookieAuthenticationConverter
        implements AuthenticationConverter {

    private final Function<String, Token> tokenCookieStringDeserializer;

    @Override
    public Authentication convert(HttpServletRequest request) {
        // Returning null signals "no credentials in this request" — AuthenticationFilter
        // then skips authentication and lets the chain continue (e.g. to HTTP Basic).
        if (request.getCookies() != null) {
            return Stream.of(request.getCookies())
                    .filter(cookie -> cookie.getName().equals("__Host-auth-token"))
                    .findFirst()
                    .map(cookie -> {
                        var token = tokenCookieStringDeserializer.apply(cookie.getValue());
                        // Raw cookie value is kept as credentials so it can be erased
                        // after authentication; the principal is the parsed Token.
                        return new PreAuthenticatedAuthenticationToken(token, cookie.getValue());
                    }).orElse(null);
        }
        return null;
    }
}
