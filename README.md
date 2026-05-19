# vps-sso

SSO-шлюз для самохостинга. Clerk выступает identity provider, Next.js выдаёт собственный JWT-cookie на корневом домене, nginx проверяет его через `auth_request` перед каждым запросом к защищённым сервисам.

## Архитектура

```
Браузер
  │
  ▼
nginx (443)
  │  auth_request /sso-auth  →  sso.example.com/api/auth/check
  │                                   │ 200 + X-Auth-Email
  │  ◄──────────────────────────────────
  │
  │  401 → redirect → sso.example.com/sign-in?redirect_url=...
  │                         │
  │                    Clerk UI (MFA, OAuth, etc.)
  │                         │
  │                    /api/auth/callback
  │                    ── JWT cookie (Domain=.example.com, 7d) ──►
  │                         │ redirect обратно на сервис
  │
  ▼
upstream service (127.0.0.1:PORT)
получает X-Forwarded-User, X-Forwarded-Email
```

**Почему свой JWT вместо Clerk Satellite Domains:**  
Clerk cookie по умолчанию привязан к одному домену. Satellite Domains — официальное решение, но требует дополнительной настройки на каждый сервис. Здесь SSO сам выпускает HS256-токен с `Domain=.example.com`, который подхватывается любым субдоменом без дополнительного кода на стороне сервиса.

## Возможности

- Единый логин для всех сервисов — web-приложений, API, стороннего ПО без OAuth
- Поддержка Bearer-токена для CLI и скриптов
- Hard logout с отзывом Clerk-сессии на сервере
- Identity propagation через заголовки (`X-Forwarded-User`, `X-Forwarded-Email`) — совместимо с Grafana, Portainer и другими, поддерживающими trusted-header auth
- Проверка `redirect_url` — допускаются только разрешённые домены

## Структура

```
src/
├── middleware.ts                     # Clerk: защищает всё кроме публичных маршрутов
├── lib/jwt.ts                        # sign / verify custom HS256 JWT
└── app/
    ├── page.tsx                      # Dashboard
    ├── sign-in/[[...sign-in]]/       # Clerk UI с динамическим redirect
    └── api/auth/
        ├── check/route.ts            # nginx auth_request endpoint → 200 / 401
        ├── callback/route.ts         # после Clerk-логина → выдаёт JWT cookie
        ├── token/route.ts            # Bearer-токен (30d) для CLI
        └── logout/route.ts          # отзывает Clerk-сессию + чистит cookie
nginx/conf.d/
├── sso.conf                          # конфиг SSO сервиса
└── protected-service.conf           # шаблон для каждого сервиса за SSO
```

## Требования

- VPS с nginx (с модулем `ngx_http_auth_request_module`)
- Docker + Docker Compose
- Аккаунт [Clerk](https://clerk.com) (production instance)
- Домен с поддоменами (`sso.example.com`, `service1.example.com`, …)
- SSL-сертификаты (например, Let's Encrypt / certbot)

## Установка

### 1. Clerk Dashboard

1. Создай приложение на [dashboard.clerk.com](https://dashboard.clerk.com)
2. **Domains** → добавь `sso.example.com` как основной домен
3. **Paths** → Sign-in URL: `/sign-in`
4. **Allowed redirect URLs** → добавь:
   - `https://sso.example.com/api/auth/callback`
   - `https://service1.example.com` (и другие сервисы)

### 2. Переменные окружения

```bash
cp .env.example .env
```

Заполни `.env`:

```bash
# Из Clerk Dashboard → API Keys
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_SECRET_KEY=sk_live_...

NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in

# Генерируй случайные значения:
JWT_SECRET=$(openssl rand -base64 48)
INTERNAL_SECRET=$(openssl rand -hex 32)

COOKIE_DOMAIN=example.com          # без точки
SSO_HOST=sso.example.com
ALLOWED_REDIRECT_HOSTS=example.com # через запятую если несколько доменов
```

### 3. Docker

```bash
docker compose up -d
```

Сервис поднимется на `127.0.0.1:3000`.

### 4. nginx — SSO сервис

```bash
cp nginx/conf.d/sso.conf /etc/nginx/conf.d/sso.conf
```

Замени `sso.example.com` и пути к SSL-сертификатам.

### 5. nginx — защищаемый сервис

```bash
cp nginx/conf.d/protected-service.conf /etc/nginx/conf.d/grafana.conf
```

В скопированном файле замени:

| Placeholder | Что подставить |
|---|---|
| `service1.example.com` | домен сервиса |
| `SERVICE_PORT` | порт сервиса (например `3001`) |
| `REPLACE_WITH_INTERNAL_SECRET` | значение `INTERNAL_SECRET` из `.env` |

```bash
nginx -t && nginx -s reload
```

> **Важно:** каждый backend должен слушать `127.0.0.1:PORT`, а не `0.0.0.0`. Иначе любой, кто достучится до порта напрямую, сможет подделать `X-Forwarded-User`.

## CLI и скрипты

1. Зайди в браузере на `https://sso.example.com`
2. Нажми **Получить токен (30 дней)**
3. Используй токен в запросах:

```bash
curl -H "Authorization: Bearer <token>" https://api.example.com/endpoint
```

```python
import httpx
headers = {"Authorization": "Bearer <token>"}
r = httpx.get("https://api.example.com/endpoint", headers=headers)
```

## Identity propagation

nginx передаёт upstream-сервису заголовки с данными залогиненного пользователя:

| Заголовок | Значение |
|---|---|
| `X-Forwarded-User` | email |
| `X-Forwarded-Email` | email |
| `X-Forwarded-Preferred-Username` | имя |
| `Remote-User` | email |

**Grafana** — включи `[auth.proxy]` в `grafana.ini`:
```ini
[auth.proxy]
enabled = true
header_name = X-Forwarded-User
header_property = email
auto_sign_up = true
```

## Добавить новый сервис

```bash
cp nginx/conf.d/protected-service.conf /etc/nginx/conf.d/myapp.conf
# Отредактируй server_name, SERVICE_PORT, INTERNAL_SECRET
nginx -t && nginx -s reload
```

Код самого сервиса менять не нужно — nginx сам проверяет аутентификацию.

## Переменные окружения — справочник

| Переменная | Обязательная | Описание |
|---|---|---|
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | да | Публичный ключ Clerk |
| `CLERK_SECRET_KEY` | да | Секретный ключ Clerk |
| `NEXT_PUBLIC_CLERK_SIGN_IN_URL` | да | `/sign-in` |
| `JWT_SECRET` | да | Секрет для подписи SSO JWT |
| `COOKIE_DOMAIN` | да | Корневой домен, например `example.com` |
| `SSO_HOST` | да | Хост SSO сервиса, например `sso.example.com` |
| `ALLOWED_REDIRECT_HOSTS` | да | Домены, куда можно редиректить после логина |
| `INTERNAL_SECRET` | нет | Общий секрет между nginx и SSO |

## Разработка

```bash
npm install
cp .env.example .env.local  # заполни dev-ключами Clerk
npm run dev
```

На `localhost:3000` доступен SSO сервис. Для тестирования `auth_request` без nginx можно вызвать `/api/auth/check` напрямую с куки или Bearer-заголовком.
