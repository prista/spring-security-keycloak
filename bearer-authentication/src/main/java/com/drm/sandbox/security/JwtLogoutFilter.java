package com.drm.sandbox.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor // only for private final (and @NonNull)
public class JwtLogoutFilter extends OncePerRequestFilter {
    @Setter
    private RequestMatcher requestMatcher =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/logout");
    @Setter
    private SecurityContextRepository contextRepository = new RequestAttributeSecurityContextRepository();

    private final JdbcTemplate jdbcTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) { // matches /jwt/logout (POST)
            // try to handle that request
            if (this.contextRepository.containsContext(request)) {
                // retrieve info about current user from security context
                var context = this.contextRepository.loadDeferredContext(request).get();

                if (context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken
                        && context.getAuthentication().getPrincipal() instanceof com.drm.sandbox.TokenUser user
                        && context.getAuthentication().getAuthorities().contains(new SimpleGrantedAuthority("JWT_LOGOUT"))) {
                    // save info about BLOCKED token
                    this.jdbcTemplate.update("insert into t_deactivated_token (id, c_keep_until) values (?, ?)",
                            user.getToken().id(),
                            Date.from(user.getToken().expiresAt()));
                    response.setStatus(HttpServletResponse.SC_NO_CONTENT); // return 204 status
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated with JWT");
        }
        filterChain.doFilter(request, response);
    }
}
