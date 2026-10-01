from pathlib import Path

readme = r"""# 🧱 Django API Template

A production-minded **Django REST Framework starter** designed to bootstrap backend projects quickly with a solid architecture, authentication, security, observability and common API infrastructure already configured.

The template is intentionally modular: project-specific applications can be added on top of a reusable `core` layer without having to rebuild the same backend infrastructure every time.

---

## ✨ What's Included

### 🔐 Authentication & Security

- **JWT authentication** with access/refresh tokens using SimpleJWT.
- **Refresh token rotation** and token blacklist.
- **Email/password authentication** through `dj-rest-auth` and `django-allauth`.
- **Mandatory email verification**.
- **Google OAuth / social login**.
- Protection against **email/account enumeration**.
- Configurable **rate limiting / throttling** for anonymous users, authenticated users, login, registration and sensitive/heavy endpoints.
- **CORS** configuration for separate frontend applications.
- **CSRF trusted origins** configurable through environment variables.
- Production security settings automatically enabled when `DEBUG=False`:
  - HTTPS redirect.
  - HSTS.
  - Secure cookies.
  - SameSite cookie configuration.
  - Proxy HTTPS support.
- Custom user model: `users.User`.

### 🌐 API Infrastructure

- Django REST Framework.
- **Standardized JSON responses** through a custom renderer.
- **Centralized exception handling**.
- Automatic **pagination** with configurable page size.
- Global authentication and permission defaults.
- Custom throttling classes.
- **OpenAPI 3 / Swagger documentation** with `drf-spectacular`.
- Reusable API services, utilities, responses and mixins.

### 🌎 IP & Geographic Context

- **Country detection from the client's IP address**, providing geographic context that can be used by applications for regional business rules such as:
  - Country-specific behavior.
  - Regional content.
  - Localization.
  - Pricing or currency rules.
  - Geographic restrictions.
  - Analytics and segmentation.

The template keeps this concern in the backend so individual applications do not need to implement IP handling independently.

### 🗄️ Database

The configuration supports different database environments:

- **PostgreSQL** for the standard configuration.
- **SQL Server** with Microsoft ODBC Driver 17.
- Optional **Windows Authentication** for SQL Server.
- **SQLite in-memory database** when running the test suite.

Database credentials and connection settings are managed through environment variables.

### 📦 File & Static Storage

- Local filesystem storage for development.
- Optional **Cloudflare R2 / S3-compatible storage** for media files.
- Configurable public R2 domain.
- Cache-Control headers for stored objects.
- **WhiteNoise** for compressed and hashed static files.

### 📧 Email

Email infrastructure is already configured for:

- Email verification.
- Authentication-related emails.
- SMTP delivery.
- **Resend SMTP** support.
- Gmail SMTP configuration.

During tests, Django's console email backend can be used instead of sending real emails.

### 📊 Observability & Logging

- Rich console logging during development.
- Rotating application log files.
- Separate rotating error log.
- Django request error logging.
- Application-specific loggers for authentication and users.
- **Sentry** integration for production error monitoring.
- Custom Sentry reporting middleware.

### ⚡ Performance & Caching

- Optional **Redis** cache.
- Local-memory cache fallback when Redis is disabled.
- Redis configuration works with both local development and production URLs.
- Redis can also be used by the throttling layer.

### 🧑‍💻 Developer Experience

- Pipenv-based dependency and command management.
- Docker / Docker Compose support.
- Environment-based configuration.
- Ready-made reusable `core` infrastructure.
- Example applications such as `users`, `auth` and `blog`.
- Built-in migrations, services, middleware, responses and utilities structure.

---

## 🛠️ Stack

| Technology | Purpose |
|---|---|
| **Python 3.13+** | Programming language |
| **Django 5.2** | Backend framework |
| **Django REST Framework** | REST API |
| **SimpleJWT** | JWT authentication |
| **dj-rest-auth** | Authentication endpoints |
| **django-allauth** | Account management & Google OAuth |
| **drf-spectacular** | OpenAPI / Swagger documentation |
| **django-cors-headers** | CORS |
| **python-decouple** | Environment configuration |
| **PostgreSQL** | Primary relational database |
| **SQL Server** | Alternative database backend |
| **Redis** | Optional caching |
| **Cloudflare R2** | Optional object storage |
| **Sentry** | Error monitoring |
| **Rich** | Developer-friendly logging |
| **WhiteNoise** | Static file serving |
| **Docker** | Containerization |
| **Pipenv** | Dependency management |

---

## 📁 Project Structure

```text
api-template-django/
│
├── .vscode/                  # VS Code project configuration
│
├── auth/                     # Authentication-related application logic
│
├── blog/                     # Example content/blog application
│
├── config/                   # Django project configuration
│   ├── settings.py           # Main settings and infrastructure configuration
│   ├── urls.py               # Root URL configuration
│   ├── throttling.py         # Custom DRF throttling
│   ├── renderers.py          # API rendering configuration
│   ├── wsgi.py               # WSGI entry point
│   └── ...
│
├── core/                     # Shared backend infrastructure
│   ├── docs/                 # Documentation-related resources
│   ├── middleware/           # Custom middleware
│   ├── migrations/           # Core migrations
│   ├── responses/            # Reusable API response helpers
│   ├── services/             # Shared business/service logic
│   ├── utils/                # Shared utilities
│   ├── error_codes.py        # Centralized API error codes
│   ├── exceptions.py         # Custom exceptions
│   ├── middleware.py         # Shared middleware
│   ├── mixins.py             # Reusable DRF/Django mixins
│   ├── models.py             # Shared models
│   ├── permission.py         # Reusable permissions
│   ├── renderers.py          # Shared API renderers
│   ├── views.py              # Shared/base views
│   └── ...
│
├── data/                     # Data, fixtures or project seed resources
├── logs/                     # Application and error logs
├── templates/                # Email and Django templates
├── users/                    # Custom user model, profiles and user logic
│
├── .env                      # Local environment variables (not committed)
├── example.env.txt           # Environment variable reference
├── docker-compose.yml        # Local/container orchestration
├── dockerfile                # Application container image
├── entrypoint.sh             # Container startup script
├── manage.py                 # Django CLI
├── Pipfile                   # Pipenv dependencies and scripts
├── Pipfile.lock              # Locked dependency versions
├── requirements.txt          # Python requirements
├── .gitignore
└── README.md
```

### Architecture

The project separates responsibilities into three main layers:

```text
                    ┌──────────────────────┐
                    │       Django API     │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
        Applications          Core           Config
       auth / users /        Shared          Settings,
          blog              backend          URLs,
                          infrastructure     throttling
             │                 │
             └──────────┬──────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
           Database    Redis     Storage
         PostgreSQL   optional   Local / R2
         SQL Server
```

The idea is to keep **project-specific business logic inside applications** while common backend infrastructure remains reusable inside `core`.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/morkmorquecho/api-template-django.git
cd api-template-django
```

### 2. Install dependencies

```bash
pipenv install
pipenv shell
```

### 3. Configure environment variables

Create your local `.env` from the provided example:

```bash
cp example.env.txt .env
```

Then configure the required values, including:

- `SECRET_KEY`
- `DEBUG`
- `DOMAIN`
- `ALLOWED_HOSTS`
- Database settings
- Email credentials
- Google OAuth credentials
- CORS origins
- CSRF trusted origins
- Pagination
- Rate limiting
- Optional Redis
- Optional Cloudflare R2
- Optional Sentry

> **Never commit `.env` or production credentials to the repository.**

### 4. Create and apply migrations

```bash
pipenv run mk
pipenv run mi
```

### 5. Create a superuser

```bash
pipenv run su
```

### 6. Start the development server

```bash
pipenv run r
```

The API will be available at:

```text
http://localhost:8000
```

Swagger UI:

```text
http://localhost:8000/api/schema/swagger-ui/
```

---

## 🐳 Docker

The repository includes:

```text
dockerfile
docker-compose.yml
entrypoint.sh
```

This allows the project to be run using a containerized environment instead of installing the complete stack directly on the host machine.

Typical workflow:

```bash
docker compose up --build
```

Environment variables should still be provided through the configured environment / `.env` workflow.

---

## ⚡ Handy Commands

The project defines common commands through Pipenv:

| Command | Description |
|---|---|
| `pipenv run r` | Start the development server |
| `pipenv run mk` | Create migrations |
| `pipenv run mi` | Apply migrations |
| `pipenv run su` | Create a superuser |
| `pipenv run sh` | Open the Django shell |
| `pipenv run test` | Run the test suite |
| `pipenv run st <name>` | Create a new Django app |
| `pipenv run clearsessions` | Clear expired sessions |

---

## 🚦 Rate Limiting

Rate limiting is controlled through:

```env
ACTIVE_RATES=True
```

When enabled, the API uses stricter production-oriented limits.

| Scope | Production |
|---|---:|
| Anonymous | 35/hour |
| Authenticated | 500/hour |
| Login | 5/hour |
| Register | 30/hour |
| Sensitive | 5/hour |
| Heavy | 20/hour |
| Burst | 20/min |
| Registration validation | 3/hour |

When rate limiting is disabled, development uses significantly higher limits to avoid interfering with local development.

The exact values are configured in `config/settings.py`.

---

## 🔑 JWT Configuration

The default JWT configuration includes:

- Access token lifetime: **60 minutes**
- Refresh token lifetime: **7 days**
- Refresh token rotation.
- Blacklisting of rotated refresh tokens.
- `Bearer` authentication.
- User ID based authentication.

Example:

```http
Authorization: Bearer <access_token>
```

JWT configuration lives in `config/settings.py` and is driven by the project's `SECRET_KEY`.

---

## 📚 API Documentation

OpenAPI documentation is generated automatically using **drf-spectacular**.

### Swagger UI

```text
/api/schema/swagger-ui/
```

### OpenAPI schema

```text
/api/schema/
```

Authentication is documented using Bearer JWT authentication.

---

## 🌎 Country Detection by IP

The backend includes support for determining the **country associated with the client's IP address**.

This can be useful when an application needs geographic context before executing business logic.

For example:

```text
Request
   │
   ▼
Client IP
   │
   ▼
Country detection
   │
   ├── Mexico
   ├── United States
   ├── Canada
   └── ...
         │
         ▼
   Application business rules
```

Potential use cases include:

- Regional pricing.
- Currency selection.
- Country-specific content.
- Geographic access rules.
- Localization.
- Analytics.
- Regional feature availability.

The detection mechanism should be treated as **context rather than an absolute identity signal**, since proxies, VPNs, mobile networks and reverse proxies can affect the apparent client IP.

When deploying behind a reverse proxy or load balancer, the application's proxy/IP configuration must be handled carefully to avoid trusting arbitrary client-supplied IP headers.

---

## 🗄️ Database Configuration

### PostgreSQL

The default non-SQL Server configuration uses PostgreSQL:

```env
DB_NAME=
DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=
```

### SQL Server

SQL Server can be enabled through the environment configuration and supports Windows Authentication:

```env
DB_WINDOWS_AUTH=True
```

The SQL Server configuration uses:

```text
ODBC Driver 17 for SQL Server
```

### Testing

When running tests, Django switches to an in-memory SQLite database:

```text
sqlite3 :memory:
```

This keeps the test suite independent from the development database.

---

## 🗃️ Cloudflare R2

Object storage can be enabled with:

```env
USE_R2=True
```

When enabled, the application uses Cloudflare R2 through its S3-compatible API.

Relevant configuration includes:

```env
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=
R2_BUCKET_NAME=
CLOUDFLARE_ACCOUNT_ID=
R2_PUBLIC_URL=
```

When R2 is disabled, uploaded media uses local filesystem storage.

Static files continue to use WhiteNoise with compressed manifest storage.

---

## ⚡ Redis

Redis is optional.

Enable it with:

```env
CACHES_REDIS=True
```

Development can use a local Redis instance while production can use a configured Redis URL:

```env
REDIS_URL=
```

When Redis is disabled, Django falls back to local-memory caching.

---

## 📧 Email

The project supports SMTP-based email delivery.

Email is used by the authentication system for workflows such as:

- Account verification.
- Email confirmation.
- Authentication-related notifications.

For tests, Django uses:

```python
django.core.mail.backends.console.EmailBackend
```

so emails are displayed in the console instead of being sent.

---

## 📈 Sentry

Sentry can be enabled for production error monitoring.

Configure:

```env
SDK_SENTRY=
```

Sentry is initialized when:

```env
DEBUG=False
```

The project also includes custom Sentry reporting middleware.

---

## 📝 Logging

Logs are stored in:

```text
logs/
├── django.log
└── errors.log
```

Production logging uses rotating files to prevent logs from growing indefinitely.

Development also uses **Rich** for more readable console output and tracebacks.

---

## 🔒 Production Checklist

Before deploying:

- [ ] Set `DEBUG=False`.
- [ ] Generate a unique production `SECRET_KEY`.
- [ ] Configure `ALLOWED_HOSTS`.
- [ ] Configure `CSRF_TRUSTED_ORIGINS`.
- [ ] Configure `CORS_ALLOWED_ORIGINS`.
- [ ] Set secure cookie options according to the deployment.
- [ ] Enable `ACTIVE_RATES=True`.
- [ ] Configure production database credentials.
- [ ] Configure SMTP / Resend credentials.
- [ ] Configure `SDK_SENTRY`.
- [ ] Configure Redis if required.
- [ ] Configure Cloudflare R2 if required.
- [ ] Run migrations.
- [ ] Run `collectstatic`.
- [ ] Serve Django behind a production WSGI server and reverse proxy.
- [ ] Ensure proxy HTTPS headers are configured correctly.
- [ ] Verify that client IP detection works correctly behind the reverse proxy.
- [ ] Never expose `.env` or credentials in the repository.

---

## 🧪 Testing

Run the test suite with:

```bash
pipenv run test
```

The project automatically switches to an in-memory SQLite database during tests.

For larger projects, new application tests should live alongside the application they belong to.

---

## 🧩 Adding a New Application

Create a new Django app using the existing Pipenv shortcut:

```bash
pipenv run st payments
```

Then keep application-specific logic inside the new app:

```text
payments/
├── migrations/
├── admin.py
├── apps.py
├── models.py
├── permissions.py
├── serializers.py
├── services.py
├── urls.py
├── views.py
└── tests.py
```

Shared functionality that is useful across multiple applications should generally live in `core/` instead of being duplicated.

---

## 📌 Environment Configuration

The repository includes:

```text
example.env.txt
```

Use it as the reference for the variables required by the project.

Configuration is loaded primarily through `python-decouple`, allowing settings to remain outside the source code.

The application supports environment-driven configuration for:

- Django security.
- Database connections.
- Authentication.
- Google OAuth.
- Email.
- CORS / CSRF.
- Rate limiting.
- Pagination.
- Redis.
- Cloudflare R2.
- Sentry.
- Swagger metadata.

---

## 🎯 Why This Template?

The goal is not to create another generic Django starter.

It is meant to provide the **backend foundation that repeatedly appears in real projects**:

```text
Authentication
     +
Security
     +
API conventions
     +
Rate limiting
     +
Logging
     +
Monitoring
     +
Caching
     +
Storage
     +
Email
     +
IP / geographic context
     +
Documentation
     ↓
Reusable Django backend foundation
```

Instead of spending the first days of every project configuring the same infrastructure, the application can start directly with its business logic.

---

## 📄 License

MIT. See [`LICENSE`](LICENSE).
"""

path = Path("/mnt/data/README_improved.md")
path.write_text(readme, encoding="utf-8")
print(f"Created: {path}")
