# Technical Specification – Spring Security Sandbox

## 1. Overview

A sandbox application for experimenting with Spring Security concepts.
The project demonstrates JWT-based authentication suitable for native (non-browser)
clients, layered on top of HTTP Basic for initial login.

### Core Features

- HTTP Basic authentication for initial sign-in (stateless sessions)
- `POST /jwt/tokens` endpoint that mints a pair of tokens for the authenticated user:
  - **access token** — signed JWS (HS256, MAC)
  - **refresh token** — encrypted JWE (`dir` + `A128GCM`)
- 5 different approaches to accessing the authenticated principal on `/api/v*/greetings`
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

- `security/SecurityConfig` — declares two beans:
  - `jwtAuthenticationConfigurer` — builds `JwtAuthenticationConfigurer` with
    `AccessTokenJwsStringSerializer` (MAC-signed, keyed from `jwt.access-token-key`)
    and `RefreshTokenJweStringSerializer` (direct-encrypted, keyed from
    `jwt.refresh-token-key`)
  - `securityFilterChain` — applies the JWT configurer, enables HTTP Basic, sets
    session policy to `STATELESS`, permits `/error`, restricts `/manager.html` to
    `ROLE_MANAGER`, requires authentication for everything else
- `JwtAuthenticationConfigurer` — `AbstractHttpConfigurer` that:
  - disables CSRF for `POST /jwt/tokens` via `PathPatternRequestMatcher` (Spring
    Security 7 replacement for `AntPathRequestMatcher`)
  - registers `RequestJwsTokensFilter` after `ExceptionTranslationFilter`
- `RequestJwsTokensFilter` — `OncePerRequestFilter` matched to `POST /jwt/tokens`.
  Loads the current `SecurityContext`, rejects `PreAuthenticatedAuthenticationToken`,
  builds a refresh token then an access token via configurable factories, serializes
  them and writes the pair as JSON.

### 2.2 Token Model

- `Token` — domain record describing a minted token (id, subject, authorities,
  createdAt, expiresAt)
- `Tokens` — response record `{accessToken, accessTokenExpiry, refreshToken,
  refreshTokenExpiry}`
- `DefaultRefreshTokenFactory` — `Function<Authentication, Token>`, builds the
  refresh token from an authenticated principal
- `DefaultAccessTokenFactory` — `Function<Token, Token>`, derives a shorter-lived
  access token from the refresh token
- `AccessTokenJwsStringSerializer` — `Function<Token, String>`, serializes a
  `Token` to a JWS compact string using a `JWSSigner` (default HS256)
- `RefreshTokenJweStringSerializer` — `Function<Token, String>`, serializes a
  `Token` to a JWE compact string using a `JWEEncrypter` (default `dir` + `A128GCM`)

### 2.3 Greeting Endpoints

The project demonstrates 5 ways to access the authenticated principal:

| Endpoint | Approach |
|---|---|
| `GET /api/v1/greetings` | `SecurityContextHolder.getContext().getAuthentication()` |
| `GET /api/v2/greetings` | `HttpServletRequest.getUserPrincipal()` |
| `GET /api/v3/greetings` | `@AuthenticationPrincipal UserDetails` |
| `GET /api/v4/greetings` | Functional `RouterFunction` + `request.principal()` |
| `GET /api/v5/greetings` | `Principal` method parameter |

- v1–v3, v5 are in `GreetingsRestController`
- v4 is a `RouterFunction<ServerResponse>` bean in `SecurityApplication`

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
- `server.ssl.*` — PKCS#12 keystore at
  `/Users/viktarburba/tmp/ssl/keystore/localhost.p12` (alias `localhost`,
  password `password`)
- `server.http2.enabled: true`

JWT tokens are bearer credentials, so the application is intentionally exposed
only over HTTPS. The keystore is a self-signed dev certificate; browsers will
show a warning.

### 2.6 Static Content

Served from `src/main/resources/static/`:
- `hello.html` — greeting page
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
mkdir -p /Users/viktarburba/tmp/ssl/keystore
keytool -genkeypair -alias localhost -keyalg RSA -keysize 2048 -storetype PKCS12 \
  -keystore /Users/viktarburba/tmp/ssl/keystore/localhost.p12 \
  -storepass password -keypass password -validity 365 \
  -dname "CN=localhost, OU=dev, O=dev, L=dev, S=dev, C=BY" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"
```

### 3.3 Testing

- `TestcontainersConfiguration` provides an ephemeral `PostgreSQLContainer` with
  `@ServiceConnection`, auto-overriding datasource properties
- Image: `postgres:17.4-alpine`
