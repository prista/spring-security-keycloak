package com.drm.sandbox.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Function;

public class RefreshTokenFilter extends OncePerRequestFilter {

    @Setter
    private RequestMatcher requestMatcher =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/refresh");
    @Setter
    private SecurityContextRepository contextRepository = new RequestAttributeSecurityContextRepository();
    @Setter
    private Function<Token, Token> accessTokenFactory = new DefaultAccessTokenFactory();
    @Setter
    private Function<Token, String> accessTokenStringSerializer = Objects::toString;
    @Setter
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) { // matches /jwt/refresh
            if (this.contextRepository.containsContext(request)) {
                var context = this.contextRepository.loadDeferredContext(request).get();

                if (context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken
                        && context.getAuthentication().getPrincipal() instanceof TokenUser user
                        // check whether it has refresh authority
                        && context.getAuthentication().getAuthorities().contains(new SimpleGrantedAuthority("JWT_REFRESH"))) {
                    var accessToken = this.accessTokenFactory.apply(user.getToken());
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    this.objectMapper.writeValue(response.getWriter(),
                            new Tokens(
                                    this.accessTokenStringSerializer.apply(accessToken),
                                    accessToken.expiresAt().toString(),
                                    null,
                                    null
                            ));
                    return;
                }
            }

            throw new AccessDeniedException("User must be authenticated with JWT");
        }
        filterChain.doFilter(request, response);
    }
}
