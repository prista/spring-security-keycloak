package com.drm.sandbox.controller;

import com.drm.sandbox.dto.Greetings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.security.Principal;

@Controller
public class GreetingsController {

    private final WebClient webClient;

    public GreetingsController() {
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:8083")
                .build();
    }

    @ModelAttribute("principal")
    public Mono<Principal> principal(Mono<Principal> principalMono) {
        return principalMono;
    }

    @GetMapping("/")
    public Mono<String> getGreetingsPage(Model model) {
        return this.webClient.get()
                .uri("/greetings-api/greetings")
                .retrieve()
                .bodyToMono(Greetings.class)
                .doOnNext(greetings -> model.addAttribute("greetings", greetings))
                .thenReturn("greetings");
    }
}