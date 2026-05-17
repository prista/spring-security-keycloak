package com.drm.sandbox.controller;

import com.drm.sandbox.dto.Greetings;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.client.RestClient;

import java.security.Principal;

@Controller
public class GreetingsController {

    private final RestClient restClient;

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public GreetingsController(ClientRegistrationRepository clientRegistrationRepository,
                               OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientService);

        this.restClient = RestClient.builder()
                .baseUrl("http://localhost:8081")

                // Interceptor catches every outgoing HTTP request before it actually leaves the client
                .requestInterceptor((request, body, execution) -> {
                    // 1. Check if the request is missing the "Authorization" header
                    if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
                        // 2. If the header is missing, we need to obtain an access token
                        var token = this.authorizedClientManager.authorize(
                                        OAuth2AuthorizeRequest.withClientRegistrationId("greetings-app-client-credentials")
                                                .principal("greetings-app")
                                                .build())
                                .getAccessToken().getTokenValue(); // Extract just the string value of the token
                        // 3. Add the fetched token to the request headers (as "Authorization: Bearer <token>")
                        request.getHeaders().setBearerAuth(token);
                    }
                    // 4. Finally, proceed with executing the request (now it has the token attached)
                    return execution.execute(request, body);
                })
                .build();
    }

    @ModelAttribute("principal")
    public Principal principal(Principal principal) {
        return principal;
    }

    @GetMapping("/")
    public String getGreetingsPage(Model model) {
        model.addAttribute("greetings",
                this.restClient.get()
                        .uri("/greetings-api/greetings")
                        .retrieve()
                        .body(Greetings.class));
        return "greetings";
    }
}
