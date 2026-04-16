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
exist at `/Users/viktarburba/tmp/ssl/keystore/localhost.p12`; see SPEC.md §3.2
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
GET https://localhost:8443/api/v1/greetings
GET https://localhost:8443/api/v2/greetings
GET https://localhost:8443/api/v3/greetings
GET https://localhost:8443/api/v4/greetings
GET https://localhost:8443/api/v5/greetings
Authorization: Basic ai5qYW1lc29uOnBhc3N3b3Jk
```

## Key classes

- `security/SecurityConfig` — filter chain, HTTP Basic, stateless sessions,
  `/manager.html` restricted to `ROLE_MANAGER`
- `JwtAuthenticationConfigurer` — registers `RequestJwsTokensFilter` after
  `ExceptionTranslationFilter`, disables CSRF for `POST /jwt/tokens`
- `RequestJwsTokensFilter` — matches `POST /jwt/tokens`, issues the token pair
- `AccessTokenJwsStringSerializer` / `RefreshTokenJweStringSerializer` — Nimbus
  JOSE + JWT serializers for the two token types
