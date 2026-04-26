# Spring Security + Keycloak Sandbox

A Spring Boot 4 app demonstrating dual OAuth2 authentication against Keycloak: JWT bearer tokens for APIs and OIDC browser login for humans.

## Quick Start

Prerequisites: Java 21, Maven, Docker.

```bash
docker compose up -d        # Keycloak on :8080 (realm eselpo auto-imported)
mvn spring-boot:run         # App on :8081
```

Then open http://localhost:8081/authenticated.html and log in as `manager / manager` or `user / user`.

- `/authenticated.html` — any authenticated user
- `/manager.html` — requires `ROLE_MANAGER`
- Keycloak admin console: http://localhost:8080 (`admin / admin`)

## OAuth2 Concepts

### Three roles in OAuth2

1. **Authorization Server** — Keycloak. The "passport office": verifies credentials and issues tokens.
2. **Resource Server** — the server hosting protected resources (APIs, pages). It doesn't know passwords; it only validates tokens: is this token valid? who signed it? what roles does it carry?
3. **OAuth2 Client** — an application that, *on behalf of the user*, talks to the Authorization Server to obtain a token, then uses that token.

### Yes, the Resource Server is our app

More precisely, it's the *mode* in which our app handles requests carrying `Authorization: Bearer <jwt>`. Protected resources here are `/manager.html`, `/authenticated.html`, etc. The app simply takes the JWT from the header and validates its signature via Keycloak (`issuer-uri`).

### What the OAuth2 Client is in this setup

The interesting part: **this app is simultaneously a Resource Server *and* an OAuth2 Client.** They're two independent modes inside one `SecurityFilterChain`:

- **Client mode** kicks in when an unauthenticated browser request arrives. Spring Security:
  1. Redirects the browser to Keycloak (`/oauth2/authorization/keycloak`)
  2. The user logs in at Keycloak
  3. Keycloak redirects back with a `code` to `/login/oauth2/code/keycloak`
  4. The app (as a client) exchanges the `code` for tokens over the back-channel
  5. An HTTP session is created — subsequent requests use a cookie, not a token

- **Resource Server mode** kicks in when a request carries `Authorization: Bearer ...` (e.g. from Postman or another service). No redirect — just JWT validation.

### How they interact here

Directly — **they don't**. They're two parallel ways to authenticate the same request against the same endpoints. Spring Security checks: is there a `Bearer` header? → resource server branch. No? → oauth2 login branch (redirect to Keycloak). Both produce the same result: an `Authentication` in the `SecurityContext` with roles extracted identically (the logic is duplicated in `JwtAuthenticationConverter` for JWT and in `OAuth2UserService` for OIDC).

The classic "client ↔ resource server" pairing — where the client is a *separate* application that obtains a token and calls your API with it — is **not** demonstrated here: both components live inside the same process.
