# Technical Specification – Spring Security Keycloak Sandbox

## 1. Overview

A web application demonstrating Spring Security integration with Keycloak as an OAuth2/OIDC identity provider. The app supports dual authentication: JWT bearer tokens for API access and OAuth2 browser-based login via OIDC.

### Core Features

- Dual authentication: JWT resource server + OAuth2/OIDC login
- Role-based access control via custom Keycloak claim
- Static HTML pages with role-gated access

### Tech

- Spring Boot 4.0.3 (Spring Security, OAuth2 Resource Server, OAuth2 Client)
- Java 21
- Maven
- Keycloak as identity provider

## 2. Architecture

### 2.1 High-Level Architecture

- **App:** Spring Boot web application (port 8081)
- **Identity Provider:** Keycloak server (port 8080), realm `eselpo`
- **Auth Modes:**
  - Resource Server — validates JWT bearer tokens from API clients
  - OAuth2 Client — handles browser-based OIDC login flow with Keycloak redirect

### 2.2 Application Layers

**Security layer**
- `SecurityFilterChain` — configures both auth modes and authorization rules
- `JwtAuthenticationConverter` — extracts roles from JWT tokens (API mode)
- `OAuth2UserService` — extracts roles from OIDC userinfo (browser mode)

**Presentation layer**
- Static HTML pages served from `src/main/resources/public/`

## 3. Functional Requirements

### 3.1 Authentication

**JWT Resource Server mode (API clients):**
- Client sends `Authorization: Bearer <token>`
- Token validated against Keycloak's issuer URI
- Principal extracted from `preferred_username` claim
- Roles extracted from custom `spring_sec_roles` claim

**OAuth2 Login mode (browser):**
- Unauthenticated browser requests redirect to Keycloak login page
- After authentication, Keycloak redirects back with authorization code
- App exchanges code for tokens, establishes session
- Roles extracted from OIDC userinfo's `spring_sec_roles` claim

### 3.2 Authorization Rules

| Endpoint | Access |
|----------|--------|
| `/error` | Public (permitAll) |
| `/manager.html` | Authenticated + `ROLE_MANAGER` |
| Everything else | Authenticated (any role) |

### 3.3 Role Extraction

Both auth modes use identical logic:
1. Read `spring_sec_roles` claim (list of strings)
2. Filter entries starting with `ROLE_` prefix
3. Convert to `SimpleGrantedAuthority`
4. Merge with default authorities

## 4. Non-Functional Requirements

**Security**
- Role-based endpoint protection
- JWT signature validation via Keycloak issuer URI

**Observability**
- Spring Security logging at TRACE level

## 5. Keycloak Configuration

### 5.1 Realm & Client

- **Realm:** `eselpo`
- **Client ID:** `springsecurity`
- **Client Secret:** `YVL5O9cpg8KJpSwcoVICDZCfLmLzZGPA`
- **Scope:** `openid`
- **Valid Redirect URIs:** `http://localhost:8081/*`

### 5.2 Client Mapper (Critical)

A protocol mapper must be configured in Keycloak to include roles in tokens:

- **Mapper type:** User Client Role (or similar)
- **Token Claim Name:** `spring_sec_roles`
- **Claim JSON Type:** String array
- **Include in:** ID Token, Access Token, UserInfo — all enabled

### 5.3 Users & Roles

Create users in Keycloak realm with roles such as:
- `ROLE_MANAGER` — grants access to `/manager.html`
- Other `ROLE_*` roles as needed

## 6. Endpoints & Static Pages

### 6.1 Static Pages

**`/authenticated.html`** — greeting page for any authenticated user ("Привет, аутентифицированный пользователь!")

**`/manager.html`** — greeting page for users with ROLE_MANAGER ("Привет, менеджер!")

### 6.2 OAuth2 Endpoints (auto-configured)

- `/oauth2/authorization/keycloak` — initiates OIDC login
- `/login/oauth2/code/keycloak` — handles Keycloak callback

## 7. Application Configuration

**`application.yml`:**

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/realms/eselpo
      client:
        provider:
          keycloak:
            issuer-uri: http://localhost:8080/realms/eselpo
            user-name-attribute: preferred_username
        registration:
          keycloak:
            client-id: springsecurity
            client-secret: YVL5O9cpg8KJpSwcoVICDZCfLmLzZGPA
            scope: openid
server:
  port: 8081
logging:
  level:
    org.springframework.security: TRACE
```

## 8. Development Workflow

### Prerequisites

- Java 21
- Maven 3.6+
- Docker / Docker Compose

### Steps

1. Start Keycloak: `docker compose up -d`
   - Realm `eselpo` with client, mapper, and test users is auto-imported
2. Run the app: `mvn spring-boot:run`
3. Test browser login: navigate to `http://localhost:8081/authenticated.html`
4. Test API access: send JWT bearer token to any endpoint
5. Test role access: navigate to `http://localhost:8081/manager.html` (requires ROLE_MANAGER)

### Test Users (pre-configured in realm export)

| Username  | Password  | Roles                      |
|-----------|-----------|----------------------------|
| `manager` | `manager` | `ROLE_MANAGER`, `ROLE_USER` |
| `user`    | `user`    | `ROLE_USER`                |

### Docker Setup

- `docker-compose.yml` — Keycloak service (port 8080, dev mode)
- `keycloak/config/realm-export.json` — realm config auto-imported on startup
- Admin console: `http://localhost:8080` (admin / admin)
