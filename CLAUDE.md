# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [SPEC.md](SPEC.md) for full technical specification.

## Build & Run

```bash
docker compose up -d          # Start PostgreSQL
./mvnw spring-boot:run        # Run the application (https://localhost:8443)
./mvnw compile                # Compile
./mvnw test                   # Run all tests
./mvnw package                # Build JAR
```

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

- access token — JWS, signed HS256 with `jwt.access-token-key` from `application.yml`
- refresh token — JWE, encrypted `dir` + `A128GCM` with `jwt.refresh-token-key`

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

`JwtAuthenticationConverter` accepts both the access (JWS) and refresh (JWE)
token as the `Bearer` value; `TokenAuthenticationUserDetailsService` wraps
the resulting `Token` into a `TokenUser`. `/manager.html` additionally
requires `ROLE_MANAGER` (held by `j.jameson`). An invalid or expired token
returns `403 Invalid or expired token`.

## Key classes

- `security/SecurityConfig` — filter chain, HTTP Basic, stateless sessions,
  `/manager.html` restricted to `ROLE_MANAGER`; also declares the JDBC
  `UserDetailsService` bean
- `JwtAuthenticationConfigurer` — registers `RequestJwsTokensFilter` (minting)
  after `ExceptionTranslationFilter` **and** `AuthenticationFilter` with
  `JwtAuthenticationConverter` before `CsrfFilter`. Disables CSRF for
  `POST /jwt/tokens`; a successful bearer authentication triggers
  `CsrfFilter.skipRequest`; a failure returns 403
- `RequestJwsTokensFilter` — matches `POST /jwt/tokens`, issues the token pair
- `AccessTokenJwsStringSerializer` / `RefreshTokenJweStringSerializer` — Nimbus
  JOSE + JWT serializers for the two token types
- `AccessTokenJwsStringDeserializer` / `RefreshTokenJweStringDeserializer` —
  Nimbus deserializers (parse + verify/decrypt) that map claims back to `Token`
- `JwtAuthenticationConverter` — `AuthenticationConverter` for
  `Authorization: Bearer ...`, tries access then refresh
- `TokenAuthenticationUserDetailsService` + `TokenUser` — turn a `Token` into a
  `UserDetails` for `PreAuthenticatedAuthenticationProvider`
