# APS — Auth Proxy Service

Централизованная аутентификация через **AD LDAP** с выдачей пары JWT
(access 15 мин + ротация refresh 7–30 дней), JWKS-публикацией ключей и
админ-панелью (сессии + кэш пользователей в PostgreSQL).

Реализация по ТЗ v2: Go 1.27 + chi + huma v2 (OpenAPI 3.1 из кода, ReDoc
на `/docs`), React 19 + AntD 6 + Zustand + TanStack Query/Router, GORM +
golang-migrate (PostgreSQL: кэш профилей, UUIDv7 PK, created/updated/deleted_at),
Redis (refresh-сессии + rate limiting GCRA).

## Быстрый старт (полный стек)

```bash
make dev      # собирает api+web, поднимает nginx на http://localhost:8006
```

Стек добавляет к **существующим** контейнерам (внешняя сеть docker `proxy`)
только два: `aps-api` и `aps-web`. Redis берётся из имеющегося контейнера
`redis`, PostgreSQL — из `postgresql_18` (БД `aps`, пользователь `aps`).
Mock AD (glauth) стартует в профиле `dev` с пользователями:

| логин | пароль | роль |
|---|---|---|
| `alice` | `alice_password` | admin |
| `bob` | `bob_password` | — |

- SPA: http://localhost:8006
- API: http://localhost:8006/api/v1/...
- OpenAPI: http://localhost:8006/openapi.json · ReDoc: http://localhost:8006/docs
- Метрики: http://localhost:8006/metrics · Health: `/health`, `/ready`

## Команды

```bash
make test            # go unit + web vitest
make lint            # vet/fmt + tsc
make openapi         # выгрузка openapi.yaml из Go-кода
make generate-types  # регенерация TS-клиента (@hey-api/openapi-ts)
make migrate         # миграции PostgreSQL вручную
make smoke           # end-to-end проверка логина/ротации/JWKS на :8006
make e2e             # Playwright (нужен запущенный make dev)
```

## Интеграционные тесты

```bash
docker compose --profile dev up -d glauth   # mock AD
go test -race -tags=integration ./internal/it -v   # требует redis+pg (или CI services)
```

## Переход на реальный AD

1. Создать сервисную учётку только на чтение (`sAMAccountName`, `mail`,
   `memberOf`) — не Domain Admin (S-03).
2. Заполнить `.env`: `LDAP_URL=ldaps://dc.corp.local:636`,
   `LDAP_CA_CERT_FILE` (корень внутреннего PKI), `LDAP_BIND_DN/PASSWORD`,
   `LDAP_BASE_DN`, `LDAP_ADMIN_GROUP_DN`.
3. Выключить dev-профиль: `docker compose up -d` (без `--profile dev`).
4. `DOCS_ENABLED=false` в продакшене.
5. Ключи JWT: `make keys` (или корпоративный CA), ротация — см. ниже.

## Ротация ключей подписи (S-11)

1. Сгенерировать новый ключ: `openssl genrsa -out new.pem 2048`, задать
   `JWT_KEY_ID=<новый kid>`, `JWT_PRIVATE_KEY_FILE=/keys/new.pem`.
2. Старый публичный ключ сохранить в `JWT_PREV_KEYS_DIR` как `<старый-kid>.pem`
   — он остаётся в JWKS до истечения всех access-токенов (≤ 15 мин grace).

## Архитектура

```
browser ── :8006 nginx ── /api/* ── aps-api ── LDAPS ── AD (или glauth в dev)
   │                        │
   └── SPA (React/AntD)     ├── Redis: refresh-сессии (CAS-ротация, replay detection)
                            ├── Redis: rate limiting (GCRA, общий на инстансы)
                            └── PostgreSQL: кэш профилей (GORM, миграции)
```

Ключевые решения безопасности — см. таблицу S-01…S-15 в ТЗ: LDAPS-only,
`EscapeFilter` во всех фильтрах, dummy-bind против user enumeration,
одноразовый refresh с инвалидацией семейства, HttpOnly/Secure/SameSite=Strict
cookie `aps_refresh` + `X-Requested-With`, fail-closed 503 при недоступности
AD/Redis/PG, RFC 9457 `application/problem+json` без внутренних деталей.
