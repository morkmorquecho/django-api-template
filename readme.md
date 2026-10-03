# 🧱 Django API Template

A reusable **Django REST Framework backend foundation** built with a focus on clean architecture, security, observability, scalability and production-oriented infrastructure.

This project is intentionally more than a collection of Django apps: it centralizes the backend concerns that tend to be repeated across projects and provides a structured foundation for building real-world APIs.

---

## Engineering Highlights

- Custom Django user model and authentication architecture.
- JWT authentication with refresh-token rotation and blacklist support.
- Email verification and Google OAuth.
- Account-enumeration protection.
- Configurable API throttling for authentication, sensitive and expensive endpoints.
- Standardized API responses and centralized exception handling.
- Automatic OpenAPI / Swagger documentation.
- Country detection from client IP for geographic application logic.
- PostgreSQL and SQL Server support, including SQL Server Windows Authentication.
- Optional Redis caching.
- Optional Cloudflare R2 object storage.
- Production error monitoring with Sentry.
- Structured and rotating application logs.
- Dockerized development and production-oriented containerization.
- Multi-stage Docker image.
- Non-root application container.
- Gunicorn production server.
- Environment-driven configuration.
- WhiteNoise static-file handling.
- Automatic migrations and static collection at container startup.
- Health checks for infrastructure dependencies.
- Separation between project configuration, shared infrastructure and business applications.

---

## Architecture

The project follows a layered Django structure where **application-specific logic stays inside applications**, while reusable backend infrastructure lives in `core`.

```text
                         ┌─────────────────────┐
                         │      Django API     │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
        Applications              Core                 Config
      auth / users / blog     Shared infrastructure   Project settings
              │                     │                 URLs / throttling
              │          ┌──────────┼──────────┐
              │          │          │          │
              │      Services   Middleware  Responses
              │          │          │          │
              └──────────┴──────────┴──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
          PostgreSQL              Redis             Object Storage
          SQL Server             Cache              Local / R2
```

The intention is to avoid turning `views.py` into a dumping ground for business logic and to keep reusable infrastructure independent from individual applications.

---

## Project Structure

```text
api-template-django/
│
├── .vscode/
│
├── auth/
│   └── ...                    # Authentication-related logic
│
├── blog/
│   └── ...                    # Example application
│
├── config/
│   ├── settings.py            # Django configuration
│   ├── urls.py                # Root URL configuration
│   ├── throttling.py          # Custom API throttling
│   ├── wsgi.py                # WSGI entry point
│   └── ...
│
├── core/
│   ├── docs/                  # Documentation resources
│   ├── middleware/            # Custom middleware
│   ├── migrations/            # Core migrations
│   ├── responses/             # Standard API responses
│   ├── services/              # Shared service/business logic
│   ├── utils/                 # Shared utilities
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── error_codes.py         # Centralized API error codes
│   ├── exceptions.py          # Custom exceptions
│   ├── middleware.py         # Shared middleware
│   ├── mixins.py              # Reusable mixins
│   ├── models.py              # Shared models
│   ├── permission.py          # Reusable permissions
│   ├── renderers.py           # API renderers
│   ├── tests.py
│   └── views.py
│
├── data/                      # Data / seed resources
├── logs/                      # Application logs
├── templates/                 # Email / Django templates
├── users/                     # Custom user model and user domain
│
├── .env
├── .gitignore
├── docker-compose.yml
├── dockerfile
├── entrypoint.sh
├── example.env.txt
├── manage.py
├── Pipfile
├── Pipfile.lock
├── readme
└── requirements.txt
```

---

# 🔐 Authentication & Security

### JWT

Authentication is based on **SimpleJWT** and includes:

- Access tokens.
- Refresh tokens.
- Refresh-token rotation.
- Blacklisting of rotated refresh tokens.
- Bearer authentication.
- Configurable token lifetimes.

Current configuration:

```text
Access token:   60 minutes
Refresh token:  7 days
Algorithm:      HS256
Header:         Authorization: Bearer <token>
```

### Account Security

The authentication layer includes:

- Mandatory email verification.
- Unique email addresses.
- Login by email.
- Google social authentication.
- Protection against account/email enumeration.
- Django password validators.
- Custom user model.

Authentication is built using:

```text
django-allauth
        +
dj-rest-auth
        +
SimpleJWT
```

---

# 🚦 API Throttling

The API includes multiple throttling scopes instead of relying only on a single global request limit.

Production-oriented limits include:

| Scope | Limit |
|---|---:|
| Anonymous | 35/hour |
| Authenticated | 500/hour |
| Login | 5/hour |
| Register | 30/hour |
| Sensitive | 5/hour |
| Heavy | 20/hour |
| Burst | 20/min |
| Registration validation | 3/hour |

Rate limiting can be enabled or relaxed through environment configuration, allowing development and production environments to behave differently.

Custom throttling lives in:

```text
config/throttling.py
```

---

# 🌎 IP Country Detection

The backend supports **country detection from the client's IP address**.

This provides geographic context that can be consumed by application-level business logic, for example:

```text
Client request
      │
      ▼
Client IP
      │
      ▼
Country detection
      │
      ├── Country
      └── Geographic context
             │
             ▼
      Application logic
```

Possible applications include:

- Regional pricing.
- Currency selection.
- Country-specific content.
- Geographic restrictions.
- Localization.
- Regional feature availability.
- Analytics and segmentation.

The feature is treated as geographic context rather than a reliable identity mechanism, since VPNs, proxies, mobile networks and reverse proxies can affect IP-based location.

---

# 📡 API Design

The project establishes common API infrastructure instead of implementing response and error behavior independently in every endpoint.

### Standardized responses

A custom renderer provides a consistent JSON response format.

```text
core/renderers.py
```

### Centralized exceptions

API exceptions are handled through a centralized exception handler:

```text
core/utils/exceptions.py
```

This keeps error formatting consistent across the API.

### Reusable responses

Common response behavior is organized under:

```text
core/responses/
```

### Reusable services

Shared service-level logic is separated into:

```text
core/services/
```

This allows views to remain focused on HTTP concerns while reusable business operations live outside the view layer.

### Permissions and mixins

Reusable authorization and DRF behavior are centralized under:

```text
core/permission.py
core/mixins.py
```

---

# 📚 OpenAPI / Swagger

The API is documented automatically using **drf-spectacular**.

The schema is configured with:

- OpenAPI generation.
- Bearer authentication.
- API tags.
- Request/response schema splitting.
- `/api/` schema path configuration.

Swagger UI:

```text
/api/schema/swagger-ui/
```

OpenAPI schema:

```text
/api/schema/
```

---

# 🗄️ Database Layer

The project is configured to work with multiple relational database environments.

### PostgreSQL

The standard containerized environment uses:

```text
PostgreSQL 16
```

### SQL Server

The configuration also supports SQL Server through:

```text
ODBC Driver 17 for SQL Server
```

including optional:

```text
Windows Authentication
```

### Testing

The test environment automatically switches to:

```text
SQLite :memory:
```

This keeps tests isolated from development databases.

---

# ⚡ Redis

Redis is an optional infrastructure component.

The project supports:

```text
Redis
   │
   └── Django cache
```

with a local-memory fallback when Redis is disabled.

The Docker environment includes:

```text
redis:7-alpine
```

and performs a Redis health check before starting the API service.

---

# ☁️ Cloudflare R2

The storage layer can use **Cloudflare R2** through its S3-compatible API.

Supported configuration includes:

- Access credentials.
- Bucket selection.
- Cloudflare account ID.
- Custom public domain.
- Automatic media URL configuration.
- Cache-Control headers.

When R2 is disabled, media files use local filesystem storage.

Static files are handled independently through **WhiteNoise**.

---

# 📊 Observability

## Sentry

Production error monitoring is integrated with **Sentry**.

Sentry is initialized only when the application is running outside debug mode.

```text
Application
     │
     ▼
Exception
     │
     ▼
Sentry reporting middleware
     │
     ▼
Sentry
```

## Logging

The project includes:

- Rich console logging.
- Rotating application logs.
- Dedicated error logs.
- Django request error logging.
- Authentication-specific logging.
- User-domain logging.

Log files:

```text
logs/
├── django.log
└── errors.log
```

Production log rotation is configured with:

```text
15 MB per file
10 backups
```

---

# 🐳 Containerization

Docker is not only used as a development convenience; the repository includes a production-oriented application image.

## Multi-stage Docker build

The Dockerfile uses two stages:

```text
Builder
   │
   ├── System build dependencies
   ├── Python dependencies
   └── requirements.txt
            │
            ▼
Production image
   │
   ├── Python runtime only
   ├── Installed dependencies
   ├── Application source
   └── Non-root user
```

This keeps build tooling out of the final runtime image.

## Non-root container

The application runs under a dedicated:

```text
django
```

user rather than root.

The container also creates and assigns ownership of required runtime directories such as:

```text
/app/staticfiles
/app/logs
```

## Production server

The production container starts Django through:

```text
Gunicorn
```

with:

```text
3 workers
120 second timeout
access logs → stdout
error logs → stderr
```

The application binds to the platform-provided:

```text
$PORT
```

making the container suitable for platforms such as Railway.

---

# 🧩 Container Startup

`entrypoint.sh` centralizes the production startup lifecycle:

```text
Container starts
      │
      ▼
Apply migrations
      │
      ▼
Collect static files
      │
      ▼
Start Gunicorn
```

This ensures the deployed application performs the required Django initialization steps before accepting requests.

---

# 🐳 Docker Compose

The development infrastructure is composed of independent services:

```text
┌──────────────┐
│   PostgreSQL │
│      16      │
└──────┬───────┘
       │
       │
┌──────▼───────┐
│     API      │
│    Django    │
└──────┬───────┘
       │
       │
┌──────▼───────┐
│    Redis     │
│      7       │
└──────────────┘

       +

┌──────────────┐
│   Adminer    │
└──────────────┘
```

The Compose configuration includes health checks for PostgreSQL and Redis, and the API waits for both services to become healthy before starting.

---

# 📧 Email Infrastructure

The project supports SMTP-based email delivery for authentication workflows.

Configured capabilities include:

- Email verification.
- Account confirmation.
- SMTP/TLS.
- Resend SMTP.
- Gmail SMTP.

Tests use Django's console email backend so authentication flows can be tested without sending real emails.

---

# 🔒 Production Security

When `DEBUG=False`, the configuration enables additional security controls including:

- HTTPS redirection.
- HSTS.
- HSTS subdomains.
- HSTS preload.
- Secure cookie configuration.
- SameSite cookie configuration.
- Reverse-proxy HTTPS support.
- Trusted proxy host handling.

The application also separates:

```text
CORS_ALLOWED_ORIGINS
```

from:

```text
CSRF_TRUSTED_ORIGINS
```

allowing cross-origin access and CSRF trust to be controlled independently.

---

# 🧱 Separation of Responsibilities

The template intentionally separates different types of backend concerns.

| Layer | Responsibility |
|---|---|
| `config/` | Project configuration and infrastructure |
| `users/` | User domain |
| `auth/` | Authentication domain |
| `blog/` | Example business application |
| `core/services/` | Shared service/business operations |
| `core/responses/` | API response helpers |
| `core/utils/` | Shared utilities |
| `core/middleware/` | Cross-cutting request behavior |
| `core/permission.py` | Reusable authorization |
| `core/mixins.py` | Reusable Django/DRF behavior |
| `core/renderers.py` | API representation |
| `core/exceptions.py` | Custom exception definitions |
| `core/error_codes.py` | Centralized error codes |

The goal is to keep infrastructure reusable while allowing individual applications to own their business logic.

---

# 🧪 Testing Strategy

The project is configured so the test suite does not depend on the development PostgreSQL or SQL Server instance.

When tests are executed:

```text
Django
  │
  └── SQLite in-memory database
```

This provides an isolated database environment for automated tests.

---

# 🛠️ Technology Stack

```text
Python
Django
Django REST Framework
SimpleJWT
dj-rest-auth
django-allauth
drf-spectacular
django-cors-headers
python-decouple
PostgreSQL
SQL Server
Redis
Cloudflare R2
Sentry
Rich
WhiteNoise
Gunicorn
Docker
Docker Compose
Pipenv
```

---

# 📌 Engineering Focus

This template focuses on the parts of backend development that tend to become important once an API moves beyond basic CRUD:

```text
                    ┌──────────────────┐
                    │   Business API   │
                    └────────┬─────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
 Authentication          Security             API Design
       │                     │                     │
       ├── JWT              ├── HTTPS            ├── Responses
       ├── OAuth            ├── CSRF             ├── Errors
       ├── Email            ├── CORS             ├── Pagination
       └── Verification     └── Throttling       └── OpenAPI
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
 Observability           Infrastructure        Storage
       │                     │                     │
       ├── Sentry            ├── Docker           ├── PostgreSQL
       ├── Logging           ├── Gunicorn         ├── SQL Server
       └── Monitoring        └── Redis            └── Cloudflare R2
```

The result is a backend foundation designed to demonstrate not only familiarity with Django, but also understanding of **API architecture, security, infrastructure, deployment and maintainability**.

---

## 📄 License

MIT.
"""

path = Path("/mnt/data/README_recruiter.md")
path.write_text(readme, encoding="utf-8")
print(path)
