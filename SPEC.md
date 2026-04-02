# Technical Specification – Spring Security Sandbox

## 1. Overview

A sandbox application for experimenting with Spring Security concepts.
The project demonstrates various authentication and authorization patterns.

### Core Features

- HTTP Basic authentication with DB-backed user store
- 5 different approaches to accessing the authenticated principal
- Database-driven user/password/authority management via JDBC
- Static pages: login form, 403 error page

### Tech Stack

- Java 21
- Spring Boot 4.0.3 (via `dependencyManagement`, no parent POM)
- Maven
- Spring Web (`spring-boot-starter-web`)
- Spring Security (`spring-boot-starter-security`)
- Spring JDBC (`spring-boot-starter-jdbc`)
- Spring Thymeleaf (`spring-boot-starter-thymeleaf`)
- PostgreSQL
- Lombok
- Testcontainers + `spring-boot-testcontainers` (integration tests)
- Docker Compose (local PostgreSQL)

---

## 2. Architecture

### 2.1 High-Level Architecture

Standard Spring Boot layered structure with a focus on the security layer.

Base package: `com.drm.sandbox.security`

---

### 2.2 Security Layer

All endpoints require authentication via a custom Hex-encoded credentials scheme.

- `security/SecurityConfig` — configures `SecurityFilterChain`: all requests require authentication (except `/error`), applies `HexConfigurer`
- `security/HexConfigurer` — custom `AbstractHttpConfigurer` that registers `HexAuthenticationFilter` before `BasicAuthenticationFilter` and sets up a custom `AuthenticationEntryPoint` responding with `WWW-Authenticate: Hex`
- `security/HexAuthenticationFilter` — custom `OncePerRequestFilter` that extracts `Authorization: Hex <hex-encoded username:password>` header, decodes it, and authenticates via `AuthenticationManager`
- `security/JdbcUserDetailsService` — extends `MappingSqlQuery<UserDetails>`, implements `UserDetailsService`. Loads users from PostgreSQL using a named-parameter query with `array_agg()` for authorities
- `UserDetailsService` bean is registered in `SecurityApplication`

---

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

---

### 2.4 Database Schema

Managed via `schema.sql` / `data.sql` with `spring.sql.init.mode: always`.

Tables:
- `t_user` — `id`, `c_username` (unique)
- `t_user_password` — `id_user` (FK → t_user), `c_password`
- `t_user_authority` — `id_user` (FK → t_user), `c_authority`, unique on `(id_user, c_authority)`

Default user: `dbuser` / `password` with roles `ROLE_DB_USER`, `ROLE_USER`.

---

### 2.5 Static Content

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

### 3.2 Testing

- `TestcontainersConfiguration` provides an ephemeral `PostgreSQLContainer` with `@ServiceConnection`, auto-overriding datasource properties
- Image: `postgres:17.4-alpine`
