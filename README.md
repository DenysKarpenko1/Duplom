# RiskMonitor — MVP системи моніторингу ризиків ІБ

Стек: FastAPI + SQLAlchemy (SQLite за замовчуванням, PostgreSQL через `DATABASE_URL`), Vue 3 + Pinia + Tailwind CSS + Vite, Apache ECharts.

## Запуск

Сервер (термінал 1, з папки `backend`):

    py -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
    .venv\Scripts\alembic upgrade head
    .venv\Scripts\python -m app.seed               # невеликий демонстраційний набір
    .venv\Scripts\python -m app.seed_enterprise    # або: розширений набір для експерименту
    .venv\Scripts\python -m uvicorn app.main:app --port 8000

Клієнт (термінал 2, з папки `frontend`):

    npm install
    npm run dev

Застосунок: http://localhost:5173, документація API: http://localhost:8000/docs

## Математичне ядро (`backend/app/core`)

- `attack_tree.py` — дерева атак (networkx): P(AND) = Πpᵢ, P(OR) = 1 − Π(1 − pᵢ), мінімальні набори атак, критичний шлях
- `fuzzy.py` — нечіткий висновок (scikit-fuzzy): 5 термів NIST для ймовірності, впливу й ризику, 25 правил з NIST SP 800-30 Table I-2, імплікація Ларсена, центроїд
- `combined.py` — комбінований метод і залишковий ризик з урахуванням впроваджених заходів
- `comparison.py` — метрики порівняння моделей (кореляції Спірмена/Кендалла, каппа Коена, ентропія, ties)

## Розширений набір даних

`app/seed_enterprise.py` — умовне підприємство «ТОВ Альфа-Сервіс»: 18 ІТ-активів, 17 загроз, 23 вразливості, 18 заходів захисту, 35 сценаріїв із деревами атак і 6 щомісячними раундами оцінювання (червень–листопад 2026) з поступовим впровадженням заходів. Генерація детермінована.

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
- `GET/PUT/DELETE /api/scenarios/{id}/attack-tree` — дерево атак сценарію з обчисленими ймовірностями та нечіткою оцінкою
- `POST /api/scenarios/{id}/assessments` з `"method": "combined"` — оцінювання комбінованим методом
- `GET /api/methodology/fuzzy`, `GET /api/methodology/fuzzy/infer` — функції належності, база правил, пробний висновок
- `GET /api/experiments/comparison` — порівняння матричної моделі та комбінованого методу на всіх сценаріях
- `GET /api/risks` — сценарії з останньою оцінкою (плаский формат MVP, за спаданням балу)
- `POST /api/risks` — додати ризик (довідники поповнюються автоматично; Risk = Probability × Impact)
- `DELETE /api/risks/{id}` — видалити сценарій
