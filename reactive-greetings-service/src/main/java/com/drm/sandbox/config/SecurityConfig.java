package com.drm.sandbox.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.stream.Stream;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // 'authorizeExchange' is the reactive 'authorizeHttpRequests'.
                // It operates on 'ServerWebExchange' (a reactive wrapper for HTTP request/response)
                // instead of standard blocking servlets.
                .authorizeExchange(configurer ->
                        configurer.anyExchange().authenticated())
                .oauth2ResourceServer(customizer ->
                        customizer.jwt(jwt -> {
                            // 'ReactiveJwtAuthenticationConverter' is the non-blocking version.
                            // Instead of returning a plain Authentication object, it returns a Mono<Authentication> asynchronously.
                            var jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
                            jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");

                            // Standard synchronous converters (they just return a standard Collection)
                            var jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

                            var customJwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
                            customJwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("groups");
                            customJwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

                            // 'ReactiveJwtGrantedAuthoritiesConverterAdapter' acts as a bridge.
                            // It takes our synchronous lambda logic (which outputs a standard List)
                            // and wraps the result into a reactive Flux<GrantedAuthority> so it can be
                            // seamlessly integrated into the reactive WebFlux pipeline.
                            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                                    new ReactiveJwtGrantedAuthoritiesConverterAdapter(token ->
                                            Stream.concat(jwtGrantedAuthoritiesConverter.convert(token).stream(),
                                                            customJwtGrantedAuthoritiesConverter.convert(token).stream())
                                                    .toList()));

                            jwt.jwtAuthenticationConverter(jwtAuthenticationConverter);
                        }))
                .build();
    }

}
