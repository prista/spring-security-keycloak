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
  - registers `JwtLogoutFilter` after `ExceptionTranslationFilter`
    (token deactivation on `POST /jwt/logout`), wired with the configurer's
    `JdbcTemplate`
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
- `JwtLogoutFilter` — `OncePerRequestFilter` matched to `POST /jwt/logout`. Loads
  the `SecurityContext` from `RequestAttributeSecurityContextRepository`,
  verifies the principal is a `TokenUser` carrying a `JWT_LOGOUT` authority
  (present only on refresh tokens, so logout can only be triggered with the
  refresh token), then inserts the token's `id` and `expiresAt` into
  `t_deactivated_token` and returns `204 No Content`. Any other case raises
  `AccessDeniedException`.
- `JwtAuthenticationConverter` — `AuthenticationConverter` that reads the
  `Authorization` header, requires the `Bearer ` prefix, tries to parse the
  remainder first as an access (JWS) then as a refresh (JWE) token. On success
  returns `PreAuthenticatedAuthenticationToken(Token, rawString)`; otherwise
  `null` (the filter treats `null` as "no authentication attempted").
- `TokenAuthenticationUserDetailsService` — implements
  `AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>`,
  converts the `Token` carried as principal into a `TokenUser` whose
  authorities come from the token claims. `credentialsNonExpired` is computed as
  `!exists(t_deactivated_token where id = token.id) && token.expiresAt() > now()` —
  so both expired and deactivated (logged-out) tokens are rejected here.
  Non-`Token` principals raise `UsernameNotFoundException`.
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

### 2.7 Фильтры — простыми словами

В цепочке стоят три «своих» фильтра плюс стандартные фильтры Spring Security
(HTTP Basic, CSRF, ExceptionTranslation и т.д.). Каждый из трёх отвечает за
одну конкретную задачу.

#### `RequestJwsTokensFilter` — «выдать пару токенов»

- **Когда срабатывает:** только на `POST /jwt/tokens`.
- **Что делает:** берёт уже аутентифицированного пользователя из
  `SecurityContext` (пользователь пришёл с HTTP Basic — логин/пароль), создаёт
  для него **refresh token** и из него же **access token**, сериализует оба и
  отдаёт клиенту JSON-ом.
- **Зачем:** это «точка входа» — место, где пользователь меняет логин/пароль
  на пару JWT, чтобы дальше не слать пароль с каждым запросом.
- **Важно:** если запрос уже был аутентифицирован по токену
  (`PreAuthenticatedAuthenticationToken`), фильтр отказывает — нельзя чеканить
  новые токены, предъявив старый токен, только по HTTP Basic.

#### `AuthenticationFilter` + `JwtAuthenticationConverter` — «проверить Bearer»

- **Когда срабатывает:** на любом запросе, где есть заголовок
  `Authorization: Bearer <...>`. Зарегистрирован **перед** `CsrfFilter`.
- **Что делает:**
  1. `JwtAuthenticationConverter` читает заголовок, отрезает `Bearer `,
     пробует распарсить строку сначала как access (JWS), потом как refresh
     (JWE).
  2. Если получилось — отдаёт `PreAuthenticatedAuthenticationToken`, который
     дальше обрабатывает `PreAuthenticatedAuthenticationProvider` и превращает
     `Token` в `TokenUser` (`UserDetails`).
  3. На успехе вызывает `CsrfFilter.skipRequest(request)` — для токен-запросов
     CSRF не нужен.
  4. На провале отдаёт `403 Invalid or expired token`.
- **Зачем:** это «охранник» на всех защищённых эндпоинтах. Проверяет, что
  токен настоящий, подпись/шифр валидны, срок жизни не истёк
  (`credentialsNonExpired = expiresAt > now`).

#### `RefreshTokenFilter` — «обменять refresh на новый access»

- **Когда срабатывает:** только на `POST /jwt/refresh`.
- **Что делает:** ожидает, что к этому моменту `AuthenticationFilter` уже
  положил в `SecurityContext` пользователя с refresh-токеном. Проверяет, что
  у принципала есть authority `JWT_REFRESH` (это метка «я refresh, а не
  access»), вызывает `DefaultAccessTokenFactory`, сериализует новый access и
  отдаёт JSON-ом.
- **Зачем:** продлить сессию без повторного ввода пароля. Сам refresh при
  этом **не обновляется** — используется повторно до истечения.
- **Защита:** authority `JWT_REFRESH` не даёт подсунуть сюда access-токен —
  у access её нет, проверка не пройдёт.

#### `JwtLogoutFilter` — «деактивировать токен»

- **Когда срабатывает:** только на `POST /jwt/logout`.
- **Что делает:** берёт `SecurityContext` из
  `RequestAttributeSecurityContextRepository`, проверяет что принципал —
  `TokenUser` и у него есть authority `JWT_LOGOUT`. Затем записывает
  `token.id` и `token.expiresAt` в таблицу `t_deactivated_token` и возвращает
  `204 No Content`. Если контекста нет или условий нет — бросает
  `AccessDeniedException`.
- **Зачем:** выключить активную сессию (например, «выйти» с устройства), не
  дожидаясь естественного истечения срока.
- **Защита:** authority `JWT_LOGOUT` есть **только у refresh-токена**
  (добавляется в `DefaultRefreshTokenFactory` и срезается в
  `DefaultAccessTokenFactory`). Поэтому логаут можно вызвать только предъявив
  refresh — access не подойдёт.

#### Почему блокируется именно refresh и как при этом «выключается» access

Короткий ответ: **access и refresh делят один и тот же `id`**, а проверка
«не деактивирован ли токен» выполняется в `TokenAuthenticationUserDetailsService`
на **каждом** запросе — и для access, и для refresh.

Детали:

1. `DefaultAccessTokenFactory.apply(refreshToken)` создаёт новый `Token`,
   передавая `refreshToken.id()` как id access-токена — он **не
   перегенерируется**. То есть у пары access+refresh для одной сессии — общий
   UUID.
2. `JwtLogoutFilter` пишет в `t_deactivated_token` этот общий UUID.
3. На любом защищённом запросе срабатывает цепочка
   `AuthenticationFilter` → `PreAuthenticatedAuthenticationProvider` →
   `TokenAuthenticationUserDetailsService`. Последний считает
   `credentialsNonExpired` как
   `!exists(t_deactivated_token where id = token.id) && expiresAt > now`. Если
   id найден — `credentialsNonExpired = false`, Spring Security отклонит
   аутентификацию, `AuthenticationFilter` отдаст `403 Invalid or expired
   token`.
4. Таким образом, одна запись в БД блокирует сразу и refresh (нельзя больше
   чеканить новые access через `/jwt/refresh`), и уже выданный access (он
   перестанет работать на ближайшем же запросе).

Почему «входная точка» логаута — именно refresh, а не access:

- **Единый id сессии живёт в refresh.** Access — производное, его id берётся
  у refresh. Логично «закрывать сессию» через долгоживущий токен, который и
  задаёт её идентичность.
- **Безопасность.** Access-токены короткоживущие и чаще «гуляют» по сети
  (уходят с каждым запросом). Если бы логаут разрешал access, утёкший access
  позволил бы злоумышленнику принудительно завершать сессию жертвы. Refresh
  же отправляется только на `/jwt/refresh` и `/jwt/logout` — поверхность
  утечки меньше.
- **Механизм реализован через authority.** `JWT_LOGOUT` кладётся только в
  refresh (`DefaultRefreshTokenFactory`), а `DefaultAccessTokenFactory`
  оставляет только `GRANT_*`-authority — так access физически не может пройти
  проверку в `JwtLogoutFilter`.

Замечание про «web-контроллеры»: их в проекте действительно нет — вся
обработка `/jwt/tokens`, `/jwt/refresh`, `/jwt/logout` сделана фильтрами,
которые сами пишут ответ и не передают запрос дальше в
`DispatcherServlet`. Но таблица `t_deactivated_token` читается не
контроллером, а `TokenAuthenticationUserDetailsService` — то есть **внутри
цепочки аутентификации Spring Security**, до любых контроллеров. Поэтому
блокировка действует на все защищённые эндпоинты без исключения.

#### Откуда берётся **refresh token**

1. Клиент логинится HTTP Basic-ом на `POST /jwt/tokens`.
2. `RequestJwsTokensFilter` берёт `Authentication` и передаёт в
   `DefaultRefreshTokenFactory` (`Function<Authentication, Token>`).
3. Фабрика собирает `Token` с authority-ями:
   - `JWT_REFRESH` — метка «это refresh»;
   - `JWT_LOGOUT` — нужен для логаута;
   - `GRANT_<ROLE>` — **оригинальные роли пользователя с префиксом**, чтобы
     потом их можно было перенести в access.
4. `RefreshTokenJweStringSerializer` превращает `Token` в JWE (`dir` +
   `A128GCM`), зашифровано ключом `jwt.refresh-token-key`. Клиент видит
   непрозрачную строку — claims спрятаны.

#### Откуда берётся **access token**

Есть два пути:

- **При первичном логине** (`POST /jwt/tokens`): `RequestJwsTokensFilter`
  сначала строит refresh, потом передаёт его в `DefaultAccessTokenFactory`
  (`Function<Token, Token>`). Фабрика:
  - срезает срок жизни до короткого (по умолчанию 5 минут);
  - оставляет только `GRANT_*` authority-и, снимая с них префикс `GRANT_` —
    так оригинальные роли `ROLE_MANAGER` и т.п. попадают в access;
  - `JWT_REFRESH` / `JWT_LOGOUT` в access **не попадают**.
  Затем `AccessTokenJwsStringSerializer` подписывает токен HS256 ключом
  `jwt.access-token-key` и выдаёт JWS. JWS — подписан, но не зашифрован: его
  claims видны всем, но подделать нельзя.

- **При рефреше** (`POST /jwt/refresh`): `RefreshTokenFilter` берёт `Token`
  из `TokenUser` (тот самый refresh, по которому пришёл запрос) и прогоняет
  через ту же `DefaultAccessTokenFactory`. Получается новый свежий access,
  refresh остаётся прежним.

#### Почему access — JWS, а refresh — JWE

- **Access (JWS, HS256):** проверяется на каждом запросе, нужно быстро и
  дёшево. Подписи достаточно, чтобы гарантировать целостность.
- **Refresh (JWE, `dir` + `A128GCM`):** содержит «служебные» authority-и
  (`JWT_REFRESH`, `JWT_LOGOUT`, `GRANT_*`), которые клиенту знать не нужно —
  поэтому токен шифруется, а не просто подписывается.

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
