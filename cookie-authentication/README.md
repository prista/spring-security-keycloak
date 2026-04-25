# JWT-аутентификация через cookie — на пальцах

Этот модуль показывает, как делать JWT-аутентификацию для **браузера** (SPA, PWA),
а не для бекенд-к-бекенду. Главная идея: токен живёт в cookie, а не в localStorage
и не в заголовке `Authorization`, который SPA должна руками подставлять.

## Зачем cookie, а не Bearer-заголовок

В `bearer-authentication/` токен возвращается в JSON, и фронт сам кладёт его в
`Authorization: Bearer ...`. Для SPA это неудобно и небезопасно:

- токен в `localStorage` доступен любому JS — XSS его утащит;
- надо вручную прикручивать заголовок к каждому fetch'у.

Cookie с флагами `HttpOnly` + `Secure` решает обе проблемы:

- `HttpOnly` — JS вообще не видит cookie, XSS не достанет;
- `Secure` — браузер шлёт её только по HTTPS;
- браузер сам прикладывает cookie к каждому запросу на тот же origin.

## Поток аутентификации (что за чем происходит)

```
1. Пользователь логинится по HTTP Basic (или форме)
        ↓
2. Spring Security успешно аутентифицировал → дёргает SessionAuthenticationStrategy
        ↓
3. TokenCookieSessionAuthenticationStrategy:
     - создаёт Token
     - сериализует в строку (JWE)
     - кладёт в cookie "__Host-auth-token"
        ↓
4. Браузер сохраняет cookie
        ↓
5. На следующем запросе браузер сам шлёт cookie
        ↓
6. TokenCookieAuthenticationConverter:
     - достаёт cookie из запроса
     - десериализует строку обратно в Token
     - оборачивает в PreAuthenticatedAuthenticationToken
        ↓
7. PreAuthenticatedAuthenticationProvider достаёт по токену
   UserDetails и кладёт Authentication в SecurityContext
        ↓
8. Запрос идёт дальше как аутентифицированный
```

## Ключевые понятия из урока — простыми словами

### «Стратегия, которая сохраняет аутентификацию в cookie»

`SessionAuthenticationStrategy` — это хук Spring Security, который вызывается
**один раз**, сразу после успешного логина. По умолчанию он работает с HTTP-сессией
(пишет `JSESSIONID`). Так как у нас сессий нет (`SessionCreationPolicy.STATELESS`),
мы подменяем дефолтную стратегию на свою — `TokenCookieSessionAuthenticationStrategy`,
которая вместо сессии пишет наш собственный cookie с JWT внутри.

> Смысл: «куда положить факт того, что юзер залогинился» — в HTTP-сессию или
> в cookie с токеном. Мы выбираем второе.

### «Генерим токен, сериализуем, сохраняем в cookie»

Шаги в `TokenCookieSessionAuthenticationStrategy.onAuthentication`:

1. `tokenCookieFactory.apply(authentication)` — собирает объект `Token`
   (id, subject, authorities, expiresAt).
2. `tokenStringSerializer.apply(token)` — превращает `Token` в строку
   (в нашем случае — JWE: зашифрованный JWT).
3. Создаётся `Cookie("__Host-auth-token", tokenString)` с флагами:
   - `Path=/`, `Domain=null` — обязательно для префикса `__Host-`;
   - `Secure=true` — только HTTPS;
   - `HttpOnly=true` — JS не видит;
   - `MaxAge` = время жизни токена.

> **Префикс `__Host-`** — это не просто «красивое имя». Браузер форсит для
> такого cookie `Secure`, `Path=/` и **запрещает** атрибут `Domain`.
> Это защищает от подмены cookie с поддоменов.

### «Конвертер вычитывает cookie и делает Authentication»

`TokenCookieAuthenticationConverter.convert(request)`:

1. Берёт из запроса cookie с именем `__Host-auth-token`.
2. Десериализует значение → `Token` (расшифровывает JWE).
3. Заворачивает в `PreAuthenticatedAuthenticationToken(token, raw)`.

Это **не** финальная `Authentication` — это «заготовка»: «вот вам токен, проверьте
его и вытащите пользователя». Дальше эту заготовку получает
`PreAuthenticatedAuthenticationProvider`, который через
`TokenAuthenticationUserDetailsService` грузит `UserDetails` из БД и собирает
полноценный `Authentication`, попадающий в `SecurityContext`.

> **Pre-authenticated** значит: «юзер уже доказал, кто он, где-то снаружи
> (в нашем случае — наличием валидного подписанного/зашифрованного токена).
> Не надо проверять пароль, надо просто загрузить его профиль».

## Карта классов модуля

| Класс | Что делает |
|---|---|
| `SecurityConfig` | Собирает фильтр-чейн, подключает `TokenCookieAuthenticationConfigurer` |
| `TokenCookieAuthenticationConfigurer` | Регистрирует фильтр чтения cookie + `PreAuthenticatedAuthenticationProvider` + хендлер логаута, который чистит cookie и заносит токен в `t_deactivated_token` |
| `TokenCookieSessionAuthenticationStrategy` | **Запись** cookie после логина |
| `TokenCookieAuthenticationConverter` | **Чтение** cookie на каждом запросе → `PreAuthenticatedAuthenticationToken` |
| `TokenCookieFactory` | Собирает объект `Token` из `Authentication` |
| `TokenCookieJweStringSerializer` | `Token` → зашифрованная JWE-строка |
| `TokenCookieJweStringDeserializer` | JWE-строка → `Token` |
| `GetCsrfTokenFilter` | Отдаёт CSRF-токен фронту (cookie-аутентификация подвержена CSRF, в отличие от Bearer) |

## Bearer vs Cookie — короткое сравнение

| | Bearer (`Authorization`) | Cookie |
|---|---|---|
| Кто шлёт | Фронт вручную | Браузер автоматически |
| Хранение на клиенте | localStorage / память JS | `HttpOnly` cookie |
| XSS может украсть? | Да | Нет |
| CSRF возможен? | Нет (нет авто-отправки) | Да → нужен CSRF-токен |
| Кому подходит | мобильные клиенты, server-to-server | SPA / PWA в браузере |

## Почему важен CSRF в этой модели

Раз cookie ходит **автоматически** на любой запрос к нашему домену, злой сайт
может тихо сделать `POST` от имени пользователя. Поэтому в cookie-варианте
CSRF-защиту **нельзя выключать** (в отличие от bearer-варианта, где она и не
нужна). Отсюда же `GetCsrfTokenFilter` — фронту нужен endpoint, чтобы получить
актуальный CSRF-токен и приложить его к мутирующим запросам.
