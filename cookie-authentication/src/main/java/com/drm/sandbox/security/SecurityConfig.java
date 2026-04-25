package com.drm.sandbox.security;

import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import java.text.ParseException;

@Configuration
public class SecurityConfig {

    @Bean
    public TokenCookieJweStringSerializer tokenCookieJweStringSerializer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey
    ) throws ParseException, KeyLengthException {
        return new TokenCookieJweStringSerializer(new DirectEncrypter(
                OctetSequenceKey.parse(cookieTokenKey)
        ));
    }


    @Bean
    public TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey,
            JdbcTemplate jdbcTemplate
    ) throws ParseException, KeyLengthException {
        return new TokenCookieAuthenticationConfigurer()
                .tokenStringDeserializer(new TokenCookieJweStringDeserializer(new DirectDecrypter(OctetSequenceKey.parse(cookieTokenKey))))
                .jdbcTemplate(jdbcTemplate);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   TokenCookieJweStringSerializer tokenCookieJweStringSerializer,
                                                   TokenCookieAuthenticationConfigurer configurer
    ) throws Exception {
        var strategy = new TokenCookieSessionAuthenticationStrategy();
        strategy.setTokenStringSerializer(tokenCookieJweStringSerializer);

        http
                .httpBasic(Customizer.withDefaults())
                //.formLogin(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                .sessionAuthenticationStrategy(strategy))
                .addFilterAfter(new GetCsrfTokenFilter(), ExceptionTranslationFilter.class)
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/manager.html", "/manager").hasRole("MANAGER")
                        .requestMatchers("/error", "/index.html").permitAll()
                        .anyRequest().authenticated())
                .csrf(
                        csrf -> csrf.csrfTokenRepository(new CookieCsrfTokenRepository())
                                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                                .sessionAuthenticationStrategy((authentication,
                                                                request,
                                                                response) -> {})
                );

        http.apply(configurer);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return username -> jdbcTemplate.query("select * from t_user where c_username = ?",
                (rs, i) -> User.builder()
                        .username(rs.getString("c_username"))
                        .password(rs.getString("c_password"))
                        .authorities(
                                jdbcTemplate.query("select c_authority from t_user_authority where id_user = ?",
                                        (rs1, i1) ->
                                                new SimpleGrantedAuthority(rs1.getString("c_authority")),
                                        rs.getInt("id")))
                        .build(), username).stream().findFirst().orElse(null);
    }

}
