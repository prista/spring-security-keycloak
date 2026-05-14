package com.drm.sandbox.controller;

import com.drm.sandbox.dto.Greetings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.Principal;

@RestController
@RequestMapping("/greetings-api/greetings")
public class GreetingsRestController {

    @GetMapping
    public Mono<Greetings> getGreetings(Mono<Principal> principalMono) {
        return principalMono.map(principal -> "Будь как дома, %s!".formatted(principal.getName()))
                .defaultIfEmpty("Будь как дома, Путник!")
                .map(Greetings::new);
    }
}
