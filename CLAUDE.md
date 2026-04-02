# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [SPEC.md](SPEC.md) for full technical specification.

## Build & Run

```bash
docker compose up -d          # Start PostgreSQL
./mvnw spring-boot:run        # Run the application
./mvnw compile                # Compile
./mvnw test                   # Run all tests
./mvnw package                # Build JAR
```

## Test user

`dbuser` / `password` (roles: `ROLE_DB_USER`, `ROLE_USER`)

Note: `spring.security.user.password` in application.yml is ignored because a custom `UserDetailsService` bean is registered.

## Sample requests

Authentication uses a custom `Hex` scheme: the `Authorization` header value is `Hex` followed by the hex-encoded `username:password` string.

```
GET http://localhost:8080/api/v1/greetings
Authorization: Hex 6462757365723a70617373776f7264

GET http://localhost:8080/api/v2/greetings
GET http://localhost:8080/api/v3/greetings
GET http://localhost:8080/api/v4/greetings
GET http://localhost:8080/api/v5/greetings
```