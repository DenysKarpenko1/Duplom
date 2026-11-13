"""Сервер застосунку: REST API системи моніторингу ризиків ІБ.

Схема БД створюється й оновлюється міграціями: alembic upgrade head
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import catalog, risks, scenarios

app = FastAPI(title="Система моніторингу ризиків ІБ", version="0.2.0")

# Дозволяємо запити з сервера розробки фронтенду
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(catalog.router, tags=["Довідники"])
app.include_router(scenarios.router, tags=["Сценарії та оцінювання"])
app.include_router(risks.router, tags=["Сумісність з MVP"])
