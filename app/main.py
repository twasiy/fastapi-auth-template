from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.core import settings

app = FastAPI(
    title=settings.TITLE,
    docs_url="/docs/v1",
    redoc_url="/redoc/v1",
    openapi_url="/openapi.json",
)

origins = settings.CORS_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)
