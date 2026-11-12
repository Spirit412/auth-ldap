# APS — Auth Proxy Service

Централизованная аутентификация через **Active Directory (LDAP)** с выдачей
пары JWT (access 15 мин + одноразовый refresh с ротацией 7–30 дней),
публикацией ключей через JWKS и административной панелью:
пользователи, сессии, LDAP-диагностика, логи состояния.

Стек: Go 1.27 + chi + huma v2 (OpenAPI 3.1 из кода, ReDoc на `/docs`),
React 19 + AntD 6 + Zustand + TanStack Query/Router, PostgreSQL (GORM +
golang-migrate), Redis (refresh-сессии + rate limiting GCRA).

---

## Структура репозитория

```text
/
├── apps/
│   ├── api/                        # Go-бэкенд (модуль aps.local/apps/api)
│   │   ├── cmd/
│   │   │   ├── api/                # entrypoint сервера (тонкий main)
│   │   │   ├── migrate/            # ручное применение миграций (up|down)
│   │   │   ├── openapi/            # выгрузка openapi.yaml из кода
│   │   │   └── healthcheck/        # probe-бинар для scratch-образа
│   │   ├── internal/
│   │   │   ├── config/             # env-конфигурация + валидация (fail-closed)
│   │   │   ├── ldap/               # LDAPS-клиент: EscapeFilter, self-bind /
│   │   │   │                       #   service-bind, dummy-bind (S-08),
│   │   │   │                       #   TestAuth с пошаговой трассировкой
│   │   │   ├── auth/               # домен: login/refresh/logout/me, роли,
│   │   │   │                       #   ошибки RFC 9457 (*APIError)
│   │   │   ├── session/            # Redis: refresh-гранты, CAS-ротация
│   │   │   │                       #   (WATCH/MULTI), replay detection
│   │   │   ├── jwks/               # keystore (RS/ES), JWKS-документ
│   │   │   ├── middleware/         # real IP (trusted proxies), request id +
│   │   │   │                       #   zerolog, recovery, auth, Redis GCRA
│   │   │   ├── httpapi/            # huma-хендлеры: auth, sessions, users,
│   │   │   │                       #   ldap-диагностика, logs, health/ready
│   │   │   ├── userstore/          # GORM-репозиторий кэша профилей
│   │   │   │                       #   + golang-migrate runner
│   │   │   ├── logstore/           # файловые логи aps-YYYYMMDD.log,
│   │   │   │                       #   ретеншн (3 дня), чтение для UI
│   │   │   ├── audit/              # структурированные security-события
│   │   │   ├── metrics/            # Prometheus-инструменты
│   │   │   └── it/                 # интеграционные тесты (-tags=integration)
│   │   ├── migrations/             # SQL (embed): 0001_users.up/down.sql
│   │   ├── vendor/                 # зависимости в репо (хост сборки
│   │   │                           #   без доступа к proxy.golang.org)
│   │   ├── Dockerfile              # build: golang:1.27.3-alpine, runtime: scratch
│   │   └── go.mod
│   └── web/                        # React 19 + AntD 6 + TypeScript + Vite
│       ├── src/
│       │   ├── app/                # TanStack Router (роутинг + guards), query client
│       │   ├── pages/              # Login, Dashboard, Users, Logs, Ldap
│       │   ├── features/           # auth (LoginForm RHF+Zod), sessions, users
│       │   ├── services/           # вызовы API (auth, sessions, users, logs, ldap)
│       │   ├── lib/                # api-клиент (401→refresh→retry, X-Requested-With),
│       │   │                       #   jwt-утилиты
│       │   ├── stores/             # Zustand: auth (токен в памяти), ui
│       │   └── components/         # ProtectedLayout
│       ├── e2e/                    # Playwright
│       ├── nginx.conf              # same-origin: SPA + /api + /.well-known
│       └── Dockerfile              # nginx:1.31.8-alpine + dist
├── packages/
│   └── shared-types/               # openapi.yaml + TS-типы (@hey-api/openapi-ts)
├── deploy/
│   └── keys/                       # JWT-ключи (gitignored); make keys
├── scripts/smoke.sh                # end-to-end проверка деплоя
├── docker-compose.yml              # auth-ldap-api + auth-ldap-web(:8006)
│                                   #   + log-init; сеть proxy (external)
├── .env                            # секреты и параметры (gitignored)
├── .env.example                    # шаблон с комментариями
├── .vscode/                        # дебаг: API (delve) + Web (Chrome/vite), env из .env.test
└── .github/workflows/ci.yml        # fmt/vet/test, OpenAPI anti-drift, web build,
                                    #   integration (redis+postgres)
```

## Особенности приложения

- **Self-bind режим**: сервисная учётка AD не нужна — проверка пароля
  выполняется bind'ом от имени самого пользователя (UPN `логин@unicont.spb`;
  на DC s0005 проверено, что `DOMAIN\user` даёт 49). Чтение displayName/mail/
  memberOf — тем же соединением. Классический service-bind остался как
  альтернатива (задайте `LDAP_BIND_DN`/`LDAP_BIND_PASSWORD`).
- **Одноразовый refresh**: ротация атомарна (CAS в Redis); повторное
  использование токена отзывает всю сессию-семейство (replay detection).
- **Роли**: членство в `LDAP_ADMIN_GROUP_DN` → claim `roles:["admin"]` на 15 мин
  (время жизни access-токена). Пока группа не задана, доступ к админке даёт
  локальный bootstrap-админ.
- **Кэш профилей в PostgreSQL**: заполняется при каждом входе; `/me` и список
  пользователей читаются из БД, без LDAP. UUIDv7 PK, created/updated/deleted_at
  (GORM soft delete).
- **Rate limiting в Redis** (GCRA): login 5/15 мин на IP+username,
  refresh 10/мин на пользователя — общий для всех инстансов.
- **Файловые логи состояния**: `aps-YYYYMMDD.log` (JSON-строки), автоудаление
  старше 3 дней, просмотр в админке.
- **Fail-closed**: недоступность LDAP/Redis/PG → 503 на auth-эндпоинтах и
  `/ready`; все ошибки — RFC 9457 `application/problem+json`.
- **OpenAPI 3.1 генерируется из Go-кода** (huma), TS-типы и клиент — из спеки
  (@hey-api/openapi-ts); CI проверяет рассинхрон (anti-drift).
- **Same-origin**: SPA и API за одним nginx, CORS выключен.

## URL и порты

| Что                  | Адрес                                         |
| -------------------- | --------------------------------------------- |
| Веб-интерфейс (SPA)  | `http://<host>:8006/`                         |
| API                  | `http://<host>:8006/api/v1/...`               |
| OpenAPI-спека        | `http://<host>:8006/openapi.json` (и `.yaml`) |
| Документация (ReDoc) | `http://<host>:8006/docs`                     |
| JWKS                 | `http://<host>:8006/.well-known/jwks.json`    |
| Health / Ready       | `http://<host>:8006/health`, `/ready`         |
| Prometheus           | `http://<host>:8006/metrics`                  |

Порт наружу — один: **8006** (nginx контейнера `auth-ldap-web`). API-контейнер
внутри сети слушает `:8080`, наружу не опубликован. Локальный дебаг в VS Code:
API на `:8080`, vite-прокси пробрасывает `/api` — launch-конфигурации в
`.vscode/launch.json`, параметры из `.env.test`.

### Эндпоинты API (18 операций)

| Метод, путь                         | Назначение                                       | Доступ               |
| ----------------------------------- | ------------------------------------------------ | -------------------- |
| POST `/api/v1/auth/login`           | вход, пара токенов + Set-Cookie `aps_refresh`    | все                  |
| POST `/api/v1/auth/refresh`         | ротация (тело или cookie)                        | предъявитель refresh |
| POST `/api/v1/auth/logout`          | отзыв сессии, сброс cookie                       | Bearer access        |
| GET `/api/v1/auth/me`               | свой профиль из кэша                             | Bearer access        |
| GET `/api/v1/auth/sessions`         | список сессий (`?username=&limit=&cursor=`)      | admin                |
| DELETE `/api/v1/auth/sessions/{id}` | отзыв сессии                                     | admin                |
| GET `/api/v1/users`                 | кэш профилей: `?q=&status=&role=&limit=&cursor=` | admin                |
| GET `/api/v1/users/{id}`            | карточка профиля (вкл. удалённые)                | admin                |
| PATCH `/api/v1/users/{id}`          | правка display_name / email (локальная)          | admin                |
| DELETE `/api/v1/users/{id}`         | soft delete + отзыв сессий пользователя          | admin                |
| POST `/api/v1/users/{id}/restore`   | восстановление после soft delete                 | admin                |
| GET `/api/v1/admin/ldap/config`     | настройки LDAP-подключения (без секретов)        | admin                |
| POST `/api/v1/admin/ldap/test`      | проверка входа с пошаговым отчётом               | admin                |
| GET `/api/v1/admin/logs/dates`      | даты доступных файлов логов                      | admin                |
| GET `/api/v1/admin/logs`            | чтение лога за дату                              | admin                |
| GET `/.well-known/jwks.json`        | публичные ключи                                  | все                  |
| GET `/health`, `/ready`             | живость / готовность (fail-closed)               | все                  |

## Настройки подключения к LDAP

Задаются в `.env` (шаблон — `.env.example`), читаются при старте; там же их
показывает страница **LDAP** в админке (секреты не возвращаются).

| Переменная                            | Значение на стенде              | Описание                                                       |
| ------------------------------------- | ------------------------------- | -------------------------------------------------------------- |
| `LDAP_URL`                            | `ldaps://s0005.unicont.spb:636` | только `ldaps://`; `ldap://` — лишь с `LDAP_STARTTLS=true`     |
| `LDAP_TLS_INSECURE`                   | `true` (временно)               | без проверки цепочки; после подключения CA — выключить         |
| `LDAP_CA_CERT_FILE`                   | —                               | PEM внутреннего CA для валидации сертификата DC                |
| `LDAP_BASE_DN`                        | `DC=unicont,DC=spb`             | база поиска                                                    |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | пусто → **self-bind**           | сервисная учётка не используется                               |
| `LDAP_USER_ATTR`                      | `sAMAccountName`                | атрибут логина в фильтре                                       |
| `LDAP_OBJECT_CLASS`                   | пусто                           | доп. условие фильтра; на этом DC не требуется                  |
| `LDAP_NAME_ATTR` / `LDAP_MAIL_ATTR`   | `displayName` / `mail`          | читаемые атрибуты                                              |
| `LDAP_UPN_SUFFIX`                     | `unicont.spb`                   | короткий логин → UPN для bind (на s0005 `DOMAIN\user` даёт 49) |
| `LDAP_NETBIOS_DOMAIN`                 | `unicont`                       | fallback-формат `DOMAIN\user`                                  |
| `LDAP_ADMIN_GROUP_DN`                 | пусто                           | группа → роль `admin`; пусто = админов через AD нет            |

Поддерживаемые формы логина: `doav`, `unicont\doav`, `doav@unicont.spb`
(UPN), `doav@unicont.com` (чужой домен — приводится к короткому имени).
Диагностика: страница **LDAP** в админке показывает настройки и выполняет
проверочный вход с пошаговым отчётом (TLS → bind → search → атрибуты → роли).

## Безопасность: что хранится и что кэшируется

### PostgreSQL (таблица `users` — только кэш профилей)

| Поле                                                      | Откуда                | Комментарий                                                                                         |
| --------------------------------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------- |
| `id`                                                      | генерируется (UUIDv7) | PK                                                                                                  |
| `username`, `dn`                                          | AD                    | логин и различающее имя                                                                             |
| `display_name`, `email`                                   | AD                    | **перезаписываются при каждом входе** этого пользователя (локальные правки через PATCH — временные) |
| `roles`                                                   | маппинг `memberOf`    | `admin`, если member группы `LDAP_ADMIN_GROUP_DN`                                                   |
| `last_login_at`, `created_at`, `updated_at`, `deleted_at` | служебные             | soft delete — `deleted_at IS NOT NULL`                                                              |

**Пароли в БД не хранятся и не хэшируются** — доменный пароль существует
только в LDAP. Поле `deleted_at` — мягкое удаление: профиль скрывается из
списков, сессии пользователя отзываются; при следующем входе строка
реактивируется (AD — источник истины). Единственное исключение из «пароли
не хранятся» — опциональный bootstrap-админ: `APS_ADMIN_PASSWORD` лежит в
`.env` рядом с прочими секретами (внутри контейнера приходит через env).

### Redis (общий инстанс, префикс `aps:`)

| Ключ                                 | Содержимое                                                         | TTL         |
| ------------------------------------ | ------------------------------------------------------------------ | ----------- |
| `aps:rt:<jti>`                       | refresh-грант: JSON {family, username, ua, ip, created, roles, dn} | 7–30 дней   |
| `aps:fam:<family_id>`                | сессия: текущий jti, username, ip, ua, created, роли               | 7–30 дней   |
| `aps:user:<username>`                | zset: family_id → created_at (индекс сессий)                       | 7–30 дней   |
| `aps:rl:login:*`, `aps:rl:refresh:*` | счётчики GCRA                                                      | окно лимита |

В Redis нет паролей и нет JWT — только метаданные сессий и счётчики.
`appendonly` общего инстанса включён — перезапуск Redis сохранит сессии.

### Файлы логов (`aps-YYYYMMDD.log`, ретеншн 3 дня)

JSON-строки: security-события (login/refresh/logout, rate_limited,
session_revoked) с `username`, `ip`, `user_agent`, `request_id`, `result`,
`jti`; HTTP-журнал (метод, путь, статус, длительность). **Пароли и полные
токены не логируются никогда** — только `jti`-ссылки.

### Прочее

- Access-токен живёт в памяти браузера (не в localStorage), refresh — только
  HttpOnly-cookie `Path=/api/v1/auth; SameSite=Strict` + `X-Requested-With`
  на всех POST (анти-CSRF).
- Приватный ключ подписи — файл (`JWT_PRIVATE_KEY_FILE`), наружу отдаётся
  только JWKS. Ротация: старые публичные ключи в `JWT_PREV_KEYS_DIR` на
  grace-период.

---

## Быстрый старт

```bash
make keys        # JWT-ключ + kid
make dev         # сборка и запуск: http://localhost:8006
make test        # go unit + web vitest
make lint        # vet/fmt + tsc
make smoke       # end-to-end против :8006
```

## Интеграционные тесты

```bash
go test -race -tags=integration ./internal/it -v
```

Требуют доступный LDAP/Redis/PG (параметры `APS_IT_*`); без каталога
LDAP-тесты пропускаются.

## Переход на реальный AD с сервисной учёткой (опционально)

Self-bind уже работает без сервисной учётки. Если потребуется классический
режим — заполните `LDAP_BIND_DN`/`LDAP_BIND_PASSWORD` (учётка только на
чтение), задайте `LDAP_CA_CERT_FILE` и выключите `LDAP_TLS_INSECURE`.
Роли при refresh начнут перечитываться из каталога автоматически.

## Ротация ключей подписи (S-11)

1. Новый ключ: `openssl genrsa -out new.pem 2048`, `JWT_KEY_ID=<новый kid>`,
   `JWT_PRIVATE_KEY_FILE=/keys/new.pem`.
2. Старый публичный ключ — в `JWT_PREV_KEYS_DIR` как `<старый-kid>.pem`
   (остаётся в JWKS до истечения всех access-токенов, ≤ 15 мин).
