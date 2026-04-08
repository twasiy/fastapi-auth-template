<div align="center">

# FastAPI Auth Template

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic%20v2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![SQLAlchemy 2.0](https://img.shields.io/badge/SQLAlchemy%202.0-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org/)
[![Alembic](https://img.shields.io/badge/Alembic-6BA531?style=for-the-badge&logo=python&logoColor=white)](https://alembic.sqlalchemy.org/)
[![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
<br />
[![Argon2](https://img.shields.io/badge/Argon2-5B9BD5?style=for-the-badge&logo=lock&logoColor=white)](https://argon2-cffi.readthedocs.io/)
[![PyJWT](https://img.shields.io/badge/PyJWT-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white)](https://pyjwt.readthedocs.io/)
[![Twilio](https://img.shields.io/badge/Twilio-F22F46?style=for-the-badge&logo=Twilio&logoColor=white)](https://www.twilio.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)

</div>

---
A robust, production-ready FastAPI boilerplate featuring a comprehensive authentication system. This template skips the "social auth" fluff and focuses on a rock-solid internal identity system, including phone verification, rate limiting, and a scalable architectural structure.

---

# ✨ Key Features

- 🔐 **Robust Auth Lifecycle** – Fully async implementation of registration, login, and secure session management. Includes dedicated flows for password updates and forgotten password recovery.

- 📧 **Dual-Layer Email Verification** – Beyond initial registration activation, the template features a specialized "Change Email" workflow that ensures the new address is verified before updating the user profile.

- 📱 **Multi-Channel OTP Verification** – Integrated Twilio support for phone verification. Includes a modular OTP system for both identity confirmation and secure phone number transitions.

- 🛡️ **Stateless Revocation (jti):** High-performance token blacklisting via Redis. Uses jti claims to revoke tokens instantly without compromising the stateless nature of JWTs.

- 🚦 **Advanced Rate Limiting:** Custom manual rate-limiting classes paired with Redis for global protection against brute-force and DDoS attempts.

- 🏗️ **Modern Textbook Architecture** – Strictly adheres to clean-code principles. Separated concerns across models/, schemas/, and services/, with a heavy emphasis on dependency injection for maximum testability.

- ⚡ **Modern Async Stack** – Built for high concurrency using FastAPI, SQLAlchemy 2.0 (async patterns), and Alembic for seamless migrations.

---

# 🛠️ Project Structure
```
├── app/                        # Main application package
│   ├── api/                    # API layer
│   │   └── v1/                 # API versioning to ensure backward compatibility
│   │       ├── dependencies/   # Reusable FastAPI dependencies (Auth, DB session, etc.)
│   │       └── endpoints/      # Route handlers (Controllers) organized by resource
│   ├── core/                   # Global configuration, security settings, and constants
│   ├── crud/                   # CRUD (Create, Read, Update, Delete) object abstractions
│   ├── db/                     # Database connection logic and async session management
│   ├── models/                 # SQLAlchemy 2.0 database models (Declarative Base)
│   ├── schemas/                # Pydantic v2 data validation and serialization models
│   ├── services/               # Business logic layer (Email, Twilio, OTP logic)
│   ├── templates/              # HTML/Jinja2 templates for email notifications
│   ├── utils/                  # Helper functions and miscellaneous shared utilities
│   ├── __init__.py             # Package initializer
│   └── main.py                 # Application entry point and middleware configuration
├── migrations/                 # Alembic database migration scripts and environment
│   └── versions/               # Individual migration version files
├── alembic.ini                 # Configuration for the Alembic migration tool
├── .env.example                # Template for required environment variables
├── .gitignore                  # Standard exclusion list for Git version control
├── README.md                   # Project documentation and setup guide
├── requirements.txt            # Project dependencies and version locking
└── tests/                      # Comprehensive test suite (Pytest) for all layers
```

---

# 🚀 Getting Started

## 📋 Prerequisites

Before you begin, ensure you have the following installed and configured:

### 🛠️ Runtime Environment

- **Python 3.10+:** The project leverages modern type hinting and async features (Python 3.11+ recommended).

- **Virtual Environment:** Use `venv`, `conda`, or `poetry` to manage dependencies.

- **Package Manager:** `pip` (standard) or `uv` for lightning-fast installs.

### 🗄️ Infrastructure & Services

- **PostgreSQL:** Primary relational database for persistent user data.

- **Redis:** Required for high-speed token blacklisting, rate limiting, and OTP caching.

- **SMTP Server:** An active mail server or service (e.g., SendGrid, Mailgun, or Gmail SMTP) for account activation and password resets.

- **Twilio Account:** Required for SMS-based phone verification and mobile OTP flows.

### 🔑 Required API Credentials

You will need to gather the following keys for your `.env` file:

- **Twilio:** `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and a `TWILIO_PHONE_NUMBER`.

- **Database:** Connection strings for both PostgreSQL and Redis.

- **Security:** A strong `SECRET_KEY` for JWT signing (`HS256`).


To keep the "textbook" feel, this installation block follows a logical progression: environment isolation, dependency management, database preparation, and execution.


## 📥 Installation & Setup

Follow these steps to get your development environment up and running.

### 1. Clone the Repository
```bash
git clone https://github.com/twasiy/fastapi-auth-template.git
cd fastapi-auth-template
```

### 2. Environment Configuration
Create a `.env` file in the root directory:
```.env.example
# Project configuration
TITLE=your-title-for-the-docs
API_V1_STR=/api/v1
FRONTEND_HOST=your-frontend-base-url
PROJECT_NAME=your-project-name

# Security configuration
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
RESET_TOKEN_EXPIRE_MINUTES=15
EMAIL_ACTIVATION_TOKEN_EXPIRE_DAYS=1

# Email backend configuration
SMTP_HOST=smtp.email.com
SMTP_PORT=587
SMTP_USER=username@example.com
SMTP_PASSWORD=your-smtp-app-password
EMAIL_FROM=username@example.com
EMAIL_FROM_NAME=your-app-name
SMTP_TLS=True
SMTP_SSL=False

# Database configuration
POSTGRES_SERVER=your-host
POSTGRES_PORT=5432
POSTGRES_USER=your-username
POSTGRES_PASSWORD=your-password
POSTGRES_DB=your-database-name

# Redis configuration
REDIS_URL=your-redis-url

# Frontend connection
CORS_ORIGINS=a-json-list-of-urls-of-your-frontend

# Twillo configuration
TWILIO_ACCOUNT_SID=your_sid_here
TWILIO_AUTH_TOKEN=your_token_here
TWILIO_PHONE_NUMBER=+1234567890

```

> **Note:** Open `.env` and populate it with your specific database credentials, Redis URL, and API keys for Twilio and SMTP.

### 3. Setup Virtual Environment
It is recommended to use a virtual environment to isolate project dependencies:
```bash
# Create the environment
python -m venv .venv

# Activate it
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 4. Install Dependencies
Install the required packages using `pip`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Database Migrations
Initialize your PostgreSQL schema using **Alembic**. This will apply all version-controlled migrations to your database:
```bash
alembic upgrade head
```

### 6. Running the Application
Start the development server using `uvicorn`. The template is configured for hot-reloading:
```bash
uvicorn app.main:app --reload
```

## ✅ Verification
Once the server is running, you can access the interactive API documentation at:
* **Swagger UI:** `http://127.0.0.1:8000/docs/v1`
* **ReDoc:** `http://127.0.0.1:8000/redoc/v1`

### 7. Running Tests
To ensure everything is configured correctly, run the test suite:
```bash
pytest
```

---

# 📜 License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this software for personal and commercial purposes. See the [LICENSE](LICENSE) file for the full text.

## 🤝 Contributing & Support

Contributions are welcome! If you find a bug or have a feature request, please open an Issue or submit a Pull Request.

- Author: Tassok Imam Wasiy

- Version: 1.0.0

- Status: Stable
