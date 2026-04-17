# CLAUDE.md

We're building the app described in @SPEC.MD. Read that file for general architectural tasks or to double-check
the exact security configuration, Keycloak setup, or application architecture.

Keep your replies extremely concise and focus on conveying the key information. No unnecessary fluff, no long code snippets.

Whenever working with any third-party library or something similar, you MUST look up the official documentation to ensure that you're working with up-to-date information.
Use the DocsExplorer subagent for efficient documentation lookup.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- **Build:** `mvn clean package`
- **Keycloak:** `docker compose up -d` (starts Keycloak on localhost:8080 with pre-configured realm)
- **Run:** `mvn spring-boot:run` (requires Keycloak on localhost:8080)

## Architecture

This is a Spring Boot 4.0.3 sandbox application using dual OAuth2 authentication with Keycloak:

- **Build tool**: Maven
- **Java**: 21
- **Framework**: Spring Boot 4.0.3 (Security, OAuth2 Resource Server, OAuth2 Client)
- **Identity Provider**: Keycloak (realm `eselpo`, client `springsecurity`)

### Key Dependencies

- `spring-boot-starter-security` — Security framework
- `spring-boot-starter-oauth2-resource-server` — JWT bearer token validation
- `spring-boot-starter-oauth2-client` — OIDC browser login flow

### Project Structure

- `src/main/java/sandbox/drm/sandbox/` — Single-class app with all security config
- `src/main/resources/public/` — Static HTML pages (Russian-language UI)
- `src/main/resources/application.yml` — Spring Boot & OAuth2 configuration
- `keycloak/config/realm-export.json` — Keycloak realm config (auto-imported via docker-compose)
