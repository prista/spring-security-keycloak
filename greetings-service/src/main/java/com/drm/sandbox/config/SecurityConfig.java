package com.drm.sandbox.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;import java.util.stream.Stream;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(configurer -> configurer.anyRequest()
                        .access(allOf(hasRole("MANAGER"), hasAuthority("SCOPE_greetings"))))
                .sessionManagement(configurer ->
                        configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable) // because stateless JWT authentication
                .oauth2ResourceServer(configurer ->
                        configurer.jwt(jwt -> {
                            // translates the parsed JWT into Authentication object
                            var jwtAuthenticationConverter = new JwtAuthenticationConverter();
                            // which claim from the JWT should be used as the Principal's name. (instead of UUID or the like)
                            jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");
                            jwt.jwtAuthenticationConverter(jwtAuthenticationConverter);

                            // Default converter: extracts scopes from the standard "scope" or "scp" claims.
                            // It automatically prepends the "SCOPE_" prefix (e.g., "greetings" becomes "SCOPE_greetings").
                            var jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

                            // Custom converter: configured to extract roles/authorities from a custom "groups" claim.
                            var customJwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
                            customJwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("groups");
                            // We remove the default "SCOPE_" prefix so that groups are mapped exactly as they are in the token.
                            customJwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

                            // Combine both standard scopes and custom groups into a single list of granted authorities.
                            // This allows Spring Security to evaluate both hasAuthority("SCOPE_...") and hasRole("...").
                            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(token ->
                                    Stream.concat(jwtGrantedAuthoritiesConverter.convert(token).stream(),
                                                    customJwtGrantedAuthoritiesConverter.convert(token).stream())
                                            .toList());
                        }))
                .build();
    }

}
