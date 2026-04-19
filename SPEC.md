# Technical Specification – Spring Security Sandbox

## 1. Overview

A sandbox application for experimenting with Spring Security concepts.
The project demonstrates JWT-based authentication suitable for native (non-browser)
clients, layered on top of HTTP Basic for initial login.

### Core Features

- HTTP Basic authentication for initial sign-in (stateless sessions)
- `POST /jwt/tokens` mints a pair of tokens for the authenticated user:
  - **access token** — short-lived JWS (HS256, MAC; default 5 min). Sent with
    every protected request; stateless and self-verifying.
  - **refresh token** — long-lived JWE (`dir` + `A128GCM`; default 1 day).
    Used only to mint a new access token; encryption hides the server-internal
    claims (`JWT_REFRESH`, `JWT_LOGOUT`, `GRANT_*`) from the client.
- `POST /jwt/refresh` accepts a refresh JWE as a bearer credential and returns
  a fresh access JWS. Enforced by a `JWT_REFRESH` authority in the refresh
  token so an access token cannot be replayed against this endpoint.
- **Bearer-token authentication** for all other protected endpoints:
  `Authorization: Bearer <access-JWS|refresh-JWE>` is handled by
  `AuthenticationFilter` + `JwtAuthenticationConverter` +
  `PreAuthenticatedAuthenticationProvider`, producing a `TokenUser`
  (a `UserDetails` that carries the original `Token`)
- 5 different approaches to accessing the authenticated principal on `/api/v*/greetings` (only v4 implemented so far)
- JDBC-backed user/authority store on PostgreSQL
- HTTPS + HTTP/2 on port `8443` using a local PKCS#12 keystore

### Tech Stack

- Java 21
- Spring Boot 4.0.3 (via `dependencyManagement`, no parent POM)
- Spring Security 7
- Maven
- Spring Web (`spring-boot-starter-web`)
- Spring Security (`spring-boot-starter-security`)
- Spring JDBC (`spring-boot-starter-jdbc`)
- Spring Thymeleaf (`spring-boot-starter-thymeleaf`)
- Nimbus JOSE + JWT (JWS/JWE serialization)
- PostgreSQL
- Lombok
- Testcontainers + `spring-boot-testcontainers` (integration tests)
- Docker Compose (local PostgreSQL)

---

## 2. Architecture

Base package: `com.drm.sandbox.security`

### 2.1 Security Layer

All endpoints require authentication; the filter chain is stateless.

- `security/SecurityConfig` — declares three beans:
  - `jwtAuthenticationConfigurer` — builds `JwtAuthenticationConfigurer` wired
    with four functions:
    - `AccessTokenJwsStringSerializer` (MAC, `jwt.access-token-key`)
    - `RefreshTokenJweStringSerializer` (`dir`, `jwt.refresh-token-key`)
    - `AccessTokenJwsStringDeserializer` (MAC-verify with the same key)
    - `RefreshTokenJweStringDeserializer` (`DirectDecrypter` with the same key)
  - `securityFilterChain` — applies the JWT configurer, enables HTTP Basic, sets
    session policy to `STATELESS`, permits `/error`, restricts `/manager.html` to
    `ROLE_MANAGER`, requires authentication for everything else
  - `userDetailsService` — JDBC implementation over `JdbcTemplate`, reads
    `t_user` + `t_user_authority`
- `JwtAuthenticationConfigurer` — `AbstractHttpConfigurer` that, in
  `configure(HttpSecurity)`:
  - registers `RequestJwsTokensFilter` after `ExceptionTranslationFilter`
    (token minting on `POST /jwt/tokens`)
  - registers an `AuthenticationFilter` with `JwtAuthenticationConverter`
    **before** `CsrfFilter` (bearer-token validation):
    - success handler calls `CsrfFilter.skipRequest(request)` so CSRF is
      bypassed for requests authenticated by a valid token
    - failure handler returns `403` with body `"Invalid or expired token"`
  - registers `RefreshTokenFilter` before `ExceptionTranslationFilter`
    (access-token minting on `POST /jwt/refresh`), wired with the configurer's
    `accessTokenStringSerializer` so the response carries a real JWS
  - registers a `PreAuthenticatedAuthenticationProvider` backed by
    `TokenAuthenticationUserDetailsService`
  - in `init()` disables CSRF for `POST /jwt/tokens` via
    `PathPatternRequestMatcher` (Spring Security 7 replacement for
    `AntPathRequestMatcher`)
- `RequestJwsTokensFilter` — `OncePerRequestFilter` matched to `POST /jwt/tokens`.
  Loads the current `SecurityContext`, rejects `PreAuthenticatedAuthenticationToken`,
  builds a refresh token then an access token via configurable factories, serializes
  them and writes the pair as JSON.
- `RefreshTokenFilter` — `OncePerRequestFilter` matched to `POST /jwt/refresh`.
  Requires a `SecurityContext` populated by the bearer-auth filter, verifies the
  principal is a `TokenUser` carrying a `JWT_REFRESH` authority (i.e. an access
  token cannot be used here), derives a new access token via `DefaultAccessTokenFactory`
  and writes it as JSON. Refresh token itself is not rotated in this implementation.
- `JwtAuthenticationConverter` — `AuthenticationConverter` that reads the
  `Authorization` header, requires the `Bearer ` prefix, tries to parse the
  remainder first as an access (JWS) then as a refresh (JWE) token. On success
  returns `PreAuthenticatedAuthenticationToken(Token, rawString)`; otherwise
  `null` (the filter treats `null` as "no authentication attempted").
- `TokenAuthenticationUserDetailsService` — implements
  `AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>`,
  converts the `Token` carried as principal into a `TokenUser` whose
  authorities come from the token claims. `credentialsNonExpired` is set to
  `token.expiresAt() > now()` — this is the main way expired tokens are
  rejected. Non-`Token` principals raise `UsernameNotFoundException`.
- `TokenUser` — extends `org.springframework.security.core.userdetails.User`
  and keeps the raw `Token` accessible via `getToken()` for downstream code.

### 2.2 Token Model

- `Token` — domain record describing a minted token (id, subject, authorities,
  createdAt, expiresAt)
- `Tokens` — response record `{accessToken, accessTokenExpiry, refreshToken,
  refreshTokenExpiry}`
- `DefaultRefreshTokenFactory` — `Function<Authentication, Token>`, builds the
  refresh token from an authenticated principal. Adds `JWT_REFRESH`, `JWT_LOGOUT`
  and `GRANT_<role>` authorities (the `GRANT_` prefix carries the original
  authorities through to the derived access token).
- `DefaultAccessTokenFactory` — `Function<Token, Token>`, derives a shorter-lived
  access token from the refresh token; keeps only the `GRANT_*` authorities,
  stripping the `GRANT_` prefix.
- `AccessTokenJwsStringSerializer` / `Deserializer` — JWS compact (de)serialization
  using `JWSSigner` / `JWSVerifier` (default HS256). Deserializer returns `null`
  on parse/verify failure.
- `RefreshTokenJweStringSerializer` / `Deserializer` — JWE compact
  (de)serialization using `JWEEncrypter` / `JWEDecrypter` (default `dir` +
  `A128GCM`). Deserializer returns `null` on parse/decrypt failure.

### 2.3 Greeting Endpoints

The project is meant to demonstrate 5 ways to access the authenticated
principal. Only `GET /api/v4/greetings` is implemented right now — a
`RouterFunction<ServerResponse>` bean in `SecurityApplication` that reads the
principal via `request.principal()`. The other four variants (v1/v2/v3/v5 in a
planned `GreetingsRestController`) are on the roadmap but not yet added.

| Endpoint | Approach | Status |
|---|---|---|
| `GET /api/v1/greetings` | `SecurityContextHolder.getContext().getAuthentication()` | planned |
| `GET /api/v2/greetings` | `HttpServletRequest.getUserPrincipal()` | planned |
| `GET /api/v3/greetings` | `@AuthenticationPrincipal UserDetails` | planned |
| `GET /api/v4/greetings` | Functional `RouterFunction` + `request.principal()` | **implemented** |
| `GET /api/v5/greetings` | `Principal` method parameter | planned |

### 2.4 Database Schema

Managed via `schema.sql` / `data.sql` with `spring.sql.init.mode: always`. The
schema script drops all tables with `cascade` before recreating them, so the
database is rebuilt from scratch on every application start.

Tables:
- `t_user` — `id`, `c_username` (unique), `c_password`
- `t_user_authority` — `id` (serial), `id_user` (FK → t_user), `c_authority`
- `t_deactivated_token` — `id` (uuid), `c_keep_until` (`> now()`)

Seed data:
- user `j.jameson` / `password` with authority `ROLE_MANAGER`

### 2.5 Transport Security

Configured in `application.yml`:
- `server.port: 8443`
- `server.ssl.*` — PKCS#12 keystore at `${user.home}/tmp/ssl/keystore/localhost.p12`
  (alias `localhost`, password `password`)
- `server.http2.enabled: true`
- `logging.level.org.springframework.security: trace` — enabled for dev to
  surface the full filter-chain decisions

JWT tokens are bearer credentials, so the application is intentionally exposed
only over HTTPS. The keystore is a self-signed dev certificate; browsers will
show a warning.

### 2.6 Static Content

Served from `src/main/resources/static/`:
- `hello.html` — greeting page
- `manager.html` — manager-only page, restricted to `ROLE_MANAGER` in
  `SecurityConfig`
- `public/sign-in.html` — login form
- `public/403.html` — access denied page

---

## 3. Infrastructure

### 3.1 Docker Compose

`docker-compose.yml` provides PostgreSQL `postgres:17.4-alpine` for local development.

```
DB name:     security
DB user:     security
DB password: security
Port:        5432
```

### 3.2 TLS Keystore

Generate the dev keystore once:

```bash
mkdir -p ~/tmp/ssl/keystore
keytool -genkeypair -alias localhost -keyalg RSA -keysize 2048 -storetype PKCS12 \
  -keystore ~/tmp/ssl/keystore/localhost.p12 \
  -storepass password -keypass password -validity 365 \
  -dname "CN=localhost, OU=dev, O=dev, L=dev, S=dev, C=BY" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"
```

### 3.3 Testing

- `TestcontainersConfiguration` provides an ephemeral `PostgreSQLContainer` with
  `@ServiceConnection`, auto-overriding datasource properties
- Image: `postgres:17.4-alpine`
