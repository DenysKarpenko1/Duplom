"""Заповнення БД тестовими даними: python -m app.seed

Скрипт очищає таблицю ризиків і додає набір записів умовного малого підприємства.
"""
from sqlalchemy import delete

from .database import Base, SessionLocal, engine
from .models import Risk
from .risk_core import calculate_risk

# (актив, загроза, вразливість, імовірність, вплив)
SEED = [
    ("База даних клієнтів", "Несанкціонований доступ зовнішнього порушника",
     "Невиправлена вразливість вебзастосунку (CVSS 9,8)", 4, 5),
    ("Корпоративний вебпортал", "Атака на відмову в обслуговуванні (DDoS)",
     "Відсутність засобів захисту від DDoS", 3, 5),
    ("Робочі станції бухгалтерії", "Зараження програмою-вимагачем",
     "Відкритий віддалений доступ (RDP), ненавчений персонал", 3, 4),
    ("Поштовий сервер", "Компрометація поштових скриньок",
     "Відсутність багатофакторної автентифікації", 3, 3),
    ("Корпоративний вебпортал", "SQL-ін'єкція",
     "Недостатня перевірка вхідних даних", 2, 4),
    ("Файловий сервер", "Витік даних через дії інсайдера",
     "Надлишкові права доступу користувачів", 2, 4),
    ("Сервер резервного копіювання", "Відмова обладнання",
     "Відсутність резервування дисків", 2, 3),
    ("База даних клієнтів", "Втрата даних через помилку адміністратора",
     "Відсутність процедури контролю змін", 1, 4),
]


def run() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.execute(delete(Risk))
        for asset, threat, vulnerability, probability, impact in SEED:
            score, level = calculate_risk(probability, impact)
            db.add(Risk(asset=asset, threat=threat, vulnerability=vulnerability,
                        probability=probability, impact=impact, score=score, level=level))
        db.commit()
    print(f"Додано записів: {len(SEED)}")


if __name__ == "__main__":
    run()
