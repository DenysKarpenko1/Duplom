"""Сервер застосунку: REST API системи моніторингу ризиків ІБ."""
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import Risk
from .risk_core import calculate_risk
from .schemas import RiskCreate, RiskOut


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Для MVP таблиці створюються під час запуску; пізніше це замінять міграції
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="Система моніторингу ризиків ІБ", version="0.1.0", lifespan=lifespan)

# Дозволяємо запити з сервера розробки фронтенду
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/risks", response_model=list[RiskOut])
def list_risks(db: Session = Depends(get_db)):
    """Усі ризики, від найнебезпечнішого до найменш небезпечного."""
    return db.scalars(select(Risk).order_by(Risk.score.desc(), Risk.id)).all()


@app.post("/api/risks", response_model=RiskOut, status_code=201)
def create_risk(payload: RiskCreate, db: Session = Depends(get_db)):
    """Додає ризик; бал і рівень рахує сервер, а не клієнт."""
    score, level = calculate_risk(payload.probability, payload.impact)
    risk = Risk(**payload.model_dump(), score=score, level=level)
    db.add(risk)
    db.commit()
    return risk


@app.delete("/api/risks/{risk_id}", status_code=204)
def delete_risk(risk_id: int, db: Session = Depends(get_db)):
    """Видаляє ризик за ідентифікатором."""
    risk = db.get(Risk, risk_id)
    if risk is None:
        raise HTTPException(status_code=404, detail="Ризик не знайдено")
    db.delete(risk)
    db.commit()
