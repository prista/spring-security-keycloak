# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [SPEC.md](SPEC.md) for full technical specification.

## Project layout

Multi-module Maven project:

- `security/` — parent POM (`<packaging>pom</packaging>`), holds shared
  `dependencyManagement`, dependencies and plugin config
- `security/bearer-authentication/` — the Spring Boot application module;
  all Java sources, resources, tests, `application.yml`, `schema.sql` /
  `data.sql` live here
- `security/docker-compose.yml` — PostgreSQL for local dev (shared across
  future modules)

Additional sibling modules (`shared`, `cookie-authentication`) are commented
out in the parent POM and not yet implemented.

## Build & Run

Run from the project root (parent POM):

```bash
docker compose up -d                                   # Start PostgreSQL
./mvnw -pl bearer-authentication spring-boot:run       # Run the app (https://localhost:8443)
./mvnw compile                                         # Compile all modules
./mvnw test                                            # Run all tests
./mvnw package                                         # Build JARs
```

`spring-boot:run` must target the `bearer-authentication` module (the parent
is packaging-only and has no main class). Alternatively `cd bearer-authentication && ../mvnw spring-boot:run`.

The app listens on **HTTPS 8443** (HTTP/2 enabled). A dev PKCS#12 keystore must
exist at `~/tmp/ssl/keystore/localhost.p12`; see SPEC.md §3.2
for the `keytool` command to generate it.

## Test user

`j.jameson` / `password` (authority: `ROLE_MANAGER`)

Seeded on every start by `schema.sql` + `data.sql` — the schema is dropped and
recreated on each run.

## Sample requests

All requests use HTTPS. With a self-signed cert, add `-k` to curl.

### 1. Obtain a token pair

```
POST https://localhost:8443/jwt/tokens
Authorization: Basic ai5qYW1lc29uOnBhc3N3b3Jk
```

Response:

```json
{
  "accessToken": "<JWS>",
  "accessTokenExpiry": "...",
  "refreshToken": "<JWE>",
  "refreshTokenExpiry": "..."
}
```

- **access token** — short-lived (5 min) bearer credential sent with every
  protected request. JWS, signed HS256 with `jwt.access-token-key`.
- **refresh token** — long-lived (1 day) credential used only to mint a new
  access token via `POST /jwt/refresh`. JWE, encrypted `dir` + `A128GCM` with
  `jwt.refresh-token-key`. Encrypting (not just signing) hides the claims from
  the client, since they are server-internal.

The split keeps the access token cheap/stateless with a small leak window and
confines the long-lived credential to a single endpoint.

> Both tokens are plaintext bearer credentials — anyone holding the string
> can use it. The app is served over HTTPS only (port `8443`, HTTP/2) so
> tokens never travel in clear on the wire.

### 2. Call the greeting endpoints (initial sign-in still HTTP Basic)

```
GET https://localhost:8443/api/v4/greetings
Authorization: Basic ai5qYW1lc29uOnBhc3N3b3Jk
```

Only v4 is implemented so far (see SPEC.md §2.3); v1/v2/v3/v5 are planned.

### 3. Call protected endpoints with the access token (Bearer)

```
GET https://localhost:8443/api/v4/greetings
Authorization: Bearer <accessToken from step 1>

GET https://localhost:8443/manager.html
Authorization: Bearer <accessToken from step 1>
```

`/manager.html` additionally requires `ROLE_MANAGER` (held by `j.jameson`).
An invalid or expired token returns `403 Invalid or expired token`.

### 4. Refresh the access token

```
POST https://localhost:8443/jwt/refresh
Authorization: Bearer <refreshToken from step 1>
```

Returns a fresh access token (refresh token is reused). The refresh token
carries a `JWT_REFRESH` authority; `RefreshTokenFilter` checks for it before
minting, so an access token cannot be used here.

## Key classes

All classes live under `bearer-authentication/src/main/java/com/drm/sandbox/security/`.

- `security/SecurityConfig` — filter chain, HTTP Basic, stateless sessions,
  `/manager.html` restricted to `ROLE_MANAGER`; declares the JDBC
  `UserDetailsService` bean
- `JwtAuthenticationConfigurer` — wires three filters: `RequestJwsTokensFilter`
  (mint on `POST /jwt/tokens`), `AuthenticationFilter` with
  `JwtAuthenticationConverter` (bearer auth, before `CsrfFilter`),
  `RefreshTokenFilter` (mint on `POST /jwt/refresh`). Disables CSRF for
  `POST /jwt/tokens`; on successful bearer auth triggers `CsrfFilter.skipRequest`;
  on failure returns 403
- `RequestJwsTokensFilter` / `RefreshTokenFilter` — issue the token pair /
  a fresh access token
- `AccessTokenJwsStringSerializer` + `Deserializer` /
  `RefreshTokenJweStringSerializer` + `Deserializer` — Nimbus JOSE + JWT
  (de)serializers for the two token types
- `JwtAuthenticationConverter` — reads `Authorization: Bearer ...`, tries access
  then refresh
- `TokenAuthenticationUserDetailsService` + `TokenUser` — turn a `Token` into a
  `UserDetails` for `PreAuthenticatedAuthenticationProvider`
