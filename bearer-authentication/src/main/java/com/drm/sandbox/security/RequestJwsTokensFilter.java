package com.drm.sandbox.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Objects;
import java.util.function.Function;


public class RequestJwsTokensFilter extends OncePerRequestFilter {

    @Setter
    private RequestMatcher requestMatcher =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/tokens");
    @Setter
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    @Setter
    private Function<Authentication, Token> refreshTokenFactory = new DefaultRefreshTokenFactory();
    @Setter
    private Function<Token, Token> accessTokenFactory = new DefaultAccessTokenFactory();
    @Setter
    private Function<Token, String> refreshTokenStringSerializer = Objects::toString; // token -> Objects.toString(token)
    @Setter
    private Function<Token, String> accessTokenStringSerializer = Objects::toString; // return (token == null) ? "null" : token.toString();
    @Setter
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        // Only handle POST /jwt/tokens; all other requests fall through the filter chain untouched.
        if (this.requestMatcher.matches(request)) {
            // Make sure the request carries a SecurityContext (populated by an earlier auth filter).
            if (this.securityContextRepository.containsContext(request)) {
                // Deferred load: the context is materialized lazily on .get().
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                // Reject pre-authenticated state: it is the raw pre-login marker, not a real user.
                if (context != null &&
                        !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                    var refreshToken = this.refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = this.accessTokenFactory.apply(refreshToken);

                    // Serialize the pair (JWS for access, JWE for refresh) and write the JSON response body.
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    this.objectMapper.writeValue(response.getWriter(),
                            new Tokens(
                                    this.accessTokenStringSerializer.apply(accessToken),
                                    accessToken.expiresAt().toString(),
                                    this.refreshTokenStringSerializer.apply(refreshToken),
                                    refreshToken.expiresAt().toString()
                            ));
                    return;
                }
                // No valid authentication on a token request -> 403.
                throw new AccessDeniedException("User must be authenticated");
            }
        }

        // Not our endpoint (or no context yet): hand the request over to the next filter.
        filterChain.doFilter(request, response);
    }
}
