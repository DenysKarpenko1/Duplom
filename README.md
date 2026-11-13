# RiskMonitor — MVP системи моніторингу ризиків ІБ

Стек: FastAPI + SQLAlchemy (SQLite за замовчуванням, PostgreSQL через `DATABASE_URL`), Vue 3 + Pinia + Tailwind CSS + Vite, Apache ECharts.

## Запуск

Сервер (термінал 1, з папки `backend`):

    py -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
    .venv\Scripts\python -m app.seed
    .venv\Scripts\python -m uvicorn app.main:app --port 8000

Клієнт (термінал 2, з папки `frontend`):

    npm install
    npm run dev

Застосунок: http://localhost:5173, документація API: http://localhost:8000/docs

## API

- `GET /api/risks` — перелік ризиків за спаданням балу
- `POST /api/risks` — додати ризик (бал і рівень рахує сервер: Risk = Probability × Impact)
- `DELETE /api/risks/{id}` — видалити ризик
