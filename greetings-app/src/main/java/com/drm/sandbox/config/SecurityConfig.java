package com.drm.sandbox.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.stream.Stream;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(customizer -> customizer
                        .anyRequest()
                        .authenticated())
                //.authorizeHttpRequests(customizer -> customizer.anyRequest().hasRole("MANAGER"))
                .oauth2Client(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults())
                .build();
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        // default Spring Security service that knows how to load OIDC users.
        OidcUserService oidcUserService = new OidcUserService();
        // return a custom implementation (lambda) to override how the user is created after login
        return userRequest -> {
            // 1. load the basic user data from the tokens.
            OidcUser oidcUser = oidcUserService.loadUser(userRequest);
            // 2. extract custom roles (groups) from the token
            // and merge them with the standard scopes (like "SCOPE_profile").
            List<GrantedAuthority> grantedAuthorities = Stream.concat(

                            // Take the standard authorities assigned by default
                            oidcUser.getAuthorities().stream(),

                            // Look inside the token for a custom claim named "groups" (e.g., from Keycloak)
                            oidcUser.getClaimAsStringList("groups").stream()
                                    // Keep only the groups that explicitly start with "ROLE_" (e.g., "ROLE_MANAGER")
                                    .filter(authority -> authority.startsWith("ROLE_"))
                                    // Convert those string names into standard Spring Security authority objects
                                    .map(SimpleGrantedAuthority::new)
                    )
                    .toList(); // Combine both streams into one single list of permissions

            // 3. Return a newly built user object containing our merged authorities.
            return new DefaultOidcUser(
                    grantedAuthorities,      // The new list of combined scopes and roles
                    oidcUser.getIdToken(),   // The original ID Token (contains user identity)
                    oidcUser.getUserInfo(),  // Extra user details (if requested from the UserInfo endpoint)
                    "preferred_username"     // Tell Spring to use "preferred_username" as the user's login name (principal.getName())
            );
        };
    }
}
