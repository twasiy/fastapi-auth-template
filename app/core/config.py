from pathlib import Path

from fastapi_mail import ConnectionConfig
from pydantic import EmailStr, PostgresDsn, SecretStr, computed_field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import List, Self

from app.schemas import BDPhone

# from dotenv import load_dotenv


# def load_env():
#     project_root = Path(__file__).resolve().parent.parent.parent
#     env_path = project_root / ".env"
#
#     if not env_path.exists():
#         raise FileNotFoundError(f".env file not found at {env_path}")
#
#     load_dotenv(dotenv_path=env_path)


def get_env_path():
    project_root = Path(__file__).resolve().parent.parent.parent
    return project_root / ".env"


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=get_env_path(),
        env_ignore_empty=True,
        case_sensitive=True,
        extra="ignore",
    )

    TITLE: str = "FastAPI Auth Template"
    API_V1_STR: str = "/api/v1"
    CORS_ORIGINS: List[str]

    SECRET_KEY: SecretStr
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    RESET_TOKEN_EXPIRE_MINUTES: int = 15
    EMAIL_ACTIVATION_TOKEN_EXPIRE_DAYS: int = 1
    EMAIL_CHANGE_TOKEN_EXPIRE_HOURS: int = 1

    FRONTEND_HOST: str = "http://localhost:3000"
    PROJECT_NAME: str

    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr = SecretStr("")
    POSTGRES_DB: str = ""

    @computed_field
    @property
    def ASYNC_DATABASE_URI(self) -> PostgresDsn:
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD.get_secret_value(),
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

    @computed_field
    @property
    def SYNC_DATABASE_URI(self) -> PostgresDsn:
        return PostgresDsn.build(
            scheme="postgresql+psycopg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD.get_secret_value(),
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

    @model_validator(mode="after")
    def _validate_postgres_db(self) -> "Settings":
        if not self.POSTGRES_DB:
            raise ValueError("POSTGRES_DB must be set")

        self.POSTGRES_DB = self.POSTGRES_DB.lstrip("/")
        return self

    SMTP_USER: str = ""
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PASSWORD: SecretStr = SecretStr("")
    SMTP_PORT: int = 587
    EMAIL_FROM: EmailStr = "example@email.com"
    EMAIL_FROM_NAME: str = ""
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False

    @model_validator(mode="after")
    def _set_default_emails_from(self) -> Self:
        if not self.EMAIL_FROM_NAME:
            self.EMAIL_FROM_NAME = self.PROJECT_NAME
        return self

    @computed_field
    @property
    def emails_enabled(self) -> bool:
        return bool(self.SMTP_HOST and self.EMAIL_FROM)

    @computed_field
    @property
    def mail_config(self) -> ConnectionConfig:
        return ConnectionConfig(
            MAIL_USERNAME=self.SMTP_USER,
            MAIL_PASSWORD=self.SMTP_PASSWORD,
            MAIL_FROM=self.EMAIL_FROM,
            MAIL_PORT=self.SMTP_PORT,
            MAIL_SERVER=self.SMTP_HOST,
            MAIL_FROM_NAME=self.EMAIL_FROM_NAME,
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True,
            TEMPLATE_FOLDER=BASE_DIR / "templates",
        )

    REDIS_URL: str

    TWILIO_ACCOUNT_SID: str
    TWILIO_AUTH_TOKEN: str
    TWILIO_PHONE_NUMBER: BDPhone


settings = Settings()  # type: ignore
