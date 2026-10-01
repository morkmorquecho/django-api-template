# 🧱 api-template-django

A production-minded **Django REST Framework starter** I use to bootstrap new backend projects faster. It ships with authentication, standardized API responses, centralized error handling, rate limiting, logging and auto-generated documentation already wired up, so a new project starts at the interesting part.

## What's Included

### Authentication and security
- **JWT authentication** with refresh tokens and token blacklist (SimpleJWT)
- **Social login with Google** (dj-rest-auth + django-allauth)
- **Mandatory email verification**
- **Configurable rate limiting** per user and per endpoint, with a switch between development and production profiles
- **CORS** configured for a separate frontend
- **Automatic HTTPS hardening** (redirect, HSTS, secure cookies) when `DEBUG=False`

### API conventions
- **Standardized response format** through a custom renderer
- **Centralized exception handling** in `core/utils/exceptions.py`
- **Automatic pagination** with a configurable page size
- **OpenAPI / Swagger docs** generated with drf-spectacular

### Observability
- **Rich-formatted console logs** in development
- **Rotating log files** with a separate error log
- **Sentry** integration for production error monitoring
- **Optional Redis cache**

### Developer experience
- **Pipenv scripts** for the most common commands
- Ready-made apps: `users`, `blog` and `core` (shared utilities)

## Stack

Python · Django 5.2 · Django REST Framework · SimpleJWT · dj-rest-auth · django-allauth · drf-spectacular · django-cors-headers · python-decouple · Sentry · Rich · Redis (optional) · SQL Server (mssql-django)

## Project Structure

```
api-template-django/
├── config/              # Settings, URLs, WSGI, custom renderers, throttling
├── users/               # Users, profiles and authentication
├── blog/                # Example content app
├── core/                # Shared utilities
│   └── utils/
│       └── exceptions.py
├── templates/           # Email templates
├── logs/                # Application and error logs
├── Pipfile
└── manage.py
```

## Quick Start

```bash
git clone https://github.com/morkmorquecho/api-template-django.git
cd api-template-django
pipenv install
pipenv shell
cp .env.example .env     # then fill in your values
pipenv run mk            # create migrations
pipenv run mi            # apply migrations
pipenv run su            # create a superuser
pipenv run r             # start the dev server
```

The API runs at `http://localhost:8000` and the Swagger UI at `http://localhost:8000/api/schema/swagger-ui/`.

**Requirements:** Python 3.13+, pipenv and a SQL Server instance with the ODBC Driver 17.

## Handy Commands

| Command | What it does |
|---------|--------------|
| `pipenv run r` | Run the development server |
| `pipenv run mk` / `mi` | Create / apply migrations |
| `pipenv run su` | Create a superuser |
| `pipenv run sh` | Open the Django shell |
| `pipenv run test` | Run the tests |
| `pipenv run st <name>` | Create a new app |
| `pipenv run clearsessions` | Clear expired sessions |

## Rate Limiting

Controlled by `ACTIVE_RATES` in your `.env`:

| Profile | Anonymous | Authenticated | Login | Register |
|---------|-----------|---------------|-------|----------|
| Development (`False`) | very high | very high | n/a | n/a |
| Production (`True`) | 35 / hour | 500 / hour | 5 / hour | 3 / hour |

## Production Notes

Set `DEBUG=False`, a unique `SECRET_KEY`, `ALLOWED_HOSTS` and `ACTIVE_RATES=True`, and configure `SDK_SENTRY`. Serve with Gunicorn behind a reverse proxy and run `collectstatic`.

## License

MIT. See [LICENSE](LICENSE).
