package com.drm.sandbox.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.util.Map;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public RouterFunction<ServerResponse> routerFunction() {
		return RouterFunctions.route()
				.GET("/api/v4/greetings", request -> {
					var userDetails = request.principal().map(Authentication.class::cast)
							.map(Authentication::getPrincipal)
							.map(UserDetails.class::cast)
							.orElseThrow();
					return ServerResponse.ok()
							.contentType(MediaType.APPLICATION_JSON)
							.body(Map.of("greeting", "Hello V4, %s!".formatted(userDetails.getUsername())));

				})
				.build();
	}

}
