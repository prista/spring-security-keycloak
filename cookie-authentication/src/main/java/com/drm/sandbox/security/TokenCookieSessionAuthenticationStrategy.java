package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.function.Function;

public class TokenCookieSessionAuthenticationStrategy
        implements SessionAuthenticationStrategy {

    @Setter
    private Function<Authentication, Token> tokenCookieFactory = new TokenCookieFactory();
    @Setter
    private Function<Token, String> tokenStringSerializer = Objects::toString; // token -> Objects.toString(token)

    public void onAuthentication(Authentication authentication,
                                 HttpServletRequest request,
                                 HttpServletResponse response)
            throws SessionAuthenticationException {
        if (authentication instanceof UsernamePasswordAuthenticationToken ) {
            // to avoid creating a token on every successful cookie authentication
            var token = tokenCookieFactory.apply(authentication);
            var tokenString = this.tokenStringSerializer.apply(token);
            // now need to save it into cookie
            // name must start with "__Host-" https://developer.mozilla.org/ru/docs/Web/HTTP/Reference/Headers/Set-Cookie
            var cookie = new Cookie("__Host-auth-token", tokenString);
            cookie.setPath("/");
            cookie.setDomain(null);
            cookie.setSecure(false);
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt()));

            response.addCookie(cookie);
        }

    }
}
