# RiskMonitor — MVP системи моніторингу ризиків ІБ

Стек: FastAPI + SQLAlchemy (SQLite за замовчуванням, PostgreSQL через `DATABASE_URL`), Vue 3 + Pinia + Tailwind CSS + Vite, Apache ECharts.

## Запуск

Сервер (термінал 1, з папки `backend`):

    py -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
    .venv\Scripts\alembic upgrade head
    .venv\Scripts\python -m app.seed
    .venv\Scripts\python -m uvicorn app.main:app --port 8000

Клієнт (термінал 2, з папки `frontend`):

    npm install
    npm run dev

Застосунок: http://localhost:5173, документація API: http://localhost:8000/docs

## База даних

Схема нормалізована до 3НФ і керується міграціями Alembic (`backend/migrations`):

- класифікатори: `asset_categories`, `threat_categories` (джерела загроз за NIST SP 800-30), `risk_levels`;
- довідники: `assets` (ІТ-активи з цінністю C/I/A), `threats`, `vulnerabilities` (CVE, CVSS), `protective_measures` (заходи захисту з ефективністю 0..1);
- зв'язки M:N: `threat_vulnerabilities`, `asset_vulnerabilities`, `measure_vulnerabilities`;
- ризики: `risk_scenarios` (актив + загроза + вразливість), `scenario_measures` (заходи сценарію зі статусом), `risk_assessments` (історія оцінювань).

Міграція `0002_normalize` переносить дані зі старої таблиці `risks` MVP і має `downgrade`.

Команди (з папки `backend`): `alembic upgrade head`, `alembic downgrade -1`, `alembic revision --autogenerate -m "..."`.

Тести: `pytest` (SQLite) або `TEST_DATABASE_URL=postgresql+psycopg://risk:risk@localhost:5432/risk_test pytest` (PostgreSQL; тестову БД буде очищено).

## API

- `GET/POST /api/assets`, `GET/PUT/DELETE /api/assets/{id}` — ІТ-активи; аналогічно `/api/threats`, `/api/vulnerabilities`, `/api/measures`, `/api/asset-categories`, `/api/threat-categories`
- `GET /api/risk-levels` — рівні ризику
- `GET/POST /api/scenarios`, `GET/DELETE /api/scenarios/{id}`, `PUT /api/scenarios/{id}/measures` — сценарії ризику та заходи
- `GET/POST /api/scenarios/{id}/assessments` — історія оцінювань сценарію
- `GET /api/risks` — сценарії з останньою оцінкою (плаский формат MVP, за спаданням балу)
- `POST /api/risks` — додати ризик (довідники поповнюються автоматично; Risk = Probability × Impact)
- `DELETE /api/risks/{id}` — видалити сценарій
