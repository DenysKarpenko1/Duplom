"""Заповнення нормалізованої БД тестовими даними умовного малого підприємства.

Спочатку застосуйте міграції, потім запустіть скрипт:
    alembic upgrade head
    python -m app.seed

Скрипт очищає довідники та ризики (класифікатори з міграції лишаються) і додає
ІТ-активи, загрози, вразливості, заходи захисту, зв'язки між ними та сценарії
з матричною оцінкою.
"""
from decimal import Decimal

from sqlalchemy import delete, select

from . import models
from .database import SessionLocal
from .assessment import combined_assessment, matrix_assessment, save_tree
from .core.attack_tree import AttackNode

# назва, категорія, власник, C, I, A
ASSETS = [
    ("База даних клієнтів", "Інформація", "Відділ продажів", 5, 5, 4),
    ("Корпоративний вебпортал", "Програмне забезпечення", "ІТ-відділ", 3, 4, 5),
    ("Робочі станції бухгалтерії", "Апаратне забезпечення", "Бухгалтерія", 4, 4, 3),
    ("Поштовий сервер", "Сервіси", "ІТ-відділ", 4, 3, 4),
    ("Файловий сервер", "Інформація", "ІТ-відділ", 4, 4, 3),
    ("Сервер резервного копіювання", "Апаратне забезпечення", "ІТ-відділ", 4, 5, 4),
]

# назва, код категорії, базова ймовірність
THREATS = [
    ("Несанкціонований доступ зовнішнього порушника", "adversarial", 4),
    ("Атака на відмову в обслуговуванні (DDoS)", "adversarial", 3),
    ("Зараження програмою-вимагачем", "adversarial", 3),
    ("Компрометація поштових скриньок", "adversarial", 3),
    ("SQL-ін'єкція", "adversarial", 2),
    ("Витік даних через дії інсайдера", "adversarial", 2),
    ("Відмова обладнання", "structural", 2),
    ("Втрата даних через помилку адміністратора", "accidental", 1),
]

# назва, CVE, CVSS, критичність (1..5)
VULNERABILITIES = [
    ("Невиправлена вразливість вебзастосунку", "CVE-2024-4577", "9.8", 5),
    ("Відсутність засобів захисту від DDoS", None, None, 4),
    ("Відкритий віддалений доступ (RDP)", None, None, 4),
    ("Недостатня обізнаність персоналу", None, None, 3),
    ("Відсутність багатофакторної автентифікації", None, None, 4),
    ("Недостатня перевірка вхідних даних", None, None, 4),
    ("Надлишкові права доступу користувачів", None, None, 3),
    ("Відсутність резервування дисків", None, None, 3),
    ("Відсутність процедури контролю змін", None, None, 2),
]

# назва, посилання на контроль, тип, ефективність, вартість, вразливості, які закриває
MEASURES = [
    ("Регулярне встановлення оновлень", "ISO 27001 A.8.8", "preventive", "0.80", "15000",
     ["Невиправлена вразливість вебзастосунку"]),
    ("Web Application Firewall", "NIST 800-53 SC-7", "preventive", "0.70", "60000",
     ["Невиправлена вразливість вебзастосунку", "Недостатня перевірка вхідних даних"]),
    ("Сервіс захисту від DDoS", "NIST 800-53 SC-5", "preventive", "0.75", "48000",
     ["Відсутність засобів захисту від DDoS"]),
    ("VPN з MFA для віддаленого доступу", "ISO 27001 A.8.5", "preventive", "0.85", "25000",
     ["Відкритий віддалений доступ (RDP)", "Відсутність багатофакторної автентифікації"]),
    ("Навчання з кібергігієни", "ISO 27001 A.6.3", "preventive", "0.50", "10000",
     ["Недостатня обізнаність персоналу"]),
    ("Рольова модель доступу та перегляд прав", "ISO 27001 A.5.15", "preventive", "0.65",
     "8000", ["Надлишкові права доступу користувачів"]),
    ("Моніторинг подій безпеки (SIEM)", "NIST 800-53 SI-4", "detective", "0.60", "90000",
     ["Невиправлена вразливість вебзастосунку", "Надлишкові права доступу користувачів"]),
    ("RAID та резервне копіювання 3-2-1", "ISO 27001 A.8.13", "corrective", "0.90", "30000",
     ["Відсутність резервування дисків", "Відсутність процедури контролю змін"]),
]

# актив, загроза, вразливість, ймовірність, вплив, [(захід, статус)]
SCENARIOS = [
    ("База даних клієнтів", "Несанкціонований доступ зовнішнього порушника",
     "Невиправлена вразливість вебзастосунку", 4, 5,
     [("Регулярне встановлення оновлень", "implemented"),
      ("Навчання з кібергігієни", "implemented"),
      ("Моніторинг подій безпеки (SIEM)", "planned")]),
    ("Корпоративний вебпортал", "Атака на відмову в обслуговуванні (DDoS)",
     "Відсутність засобів захисту від DDoS", 3, 5, [("Сервіс захисту від DDoS", "planned")]),
    ("Робочі станції бухгалтерії", "Зараження програмою-вимагачем",
     "Відкритий віддалений доступ (RDP)", 3, 4,
     [("VPN з MFA для віддаленого доступу", "implemented")]),
    ("Робочі станції бухгалтерії", "Зараження програмою-вимагачем",
     "Недостатня обізнаність персоналу", 3, 4, [("Навчання з кібергігієни", "planned")]),
    ("Поштовий сервер", "Компрометація поштових скриньок",
     "Відсутність багатофакторної автентифікації", 3, 3,
     [("VPN з MFA для віддаленого доступу", "planned")]),
    ("Корпоративний вебпортал", "SQL-ін'єкція", "Недостатня перевірка вхідних даних", 2, 4,
     [("Web Application Firewall", "implemented")]),
    ("Файловий сервер", "Витік даних через дії інсайдера",
     "Надлишкові права доступу користувачів", 2, 4,
     [("Рольова модель доступу та перегляд прав", "planned")]),
    ("Сервер резервного копіювання", "Відмова обладнання", "Відсутність резервування дисків",
     2, 3, [("RAID та резервне копіювання 3-2-1", "implemented")]),
    ("База даних клієнтів", "Втрата даних через помилку адміністратора",
     "Відсутність процедури контролю змін", 1, 4, []),
]


# Дерева атак: (назва, тип, ймовірність, вразливість, [дочірні вузли]); ключ — індекс у SCENARIOS
TREES = {
    0: ("Несанкціонований доступ до бази даних клієнтів", "OR", None, None, [
        ("Атака через вебзастосунок", "AND", None, None, [
            ("Розвідка та сканування вебпорталу", "LEAF", 0.9, None, []),
            ("Експлуатація CVE-2024-4577", "LEAF", 0.98,
             "Невиправлена вразливість вебзастосунку", []),
        ]),
        ("Вхід з викраденими обліковими даними", "AND", None, None, [
            ("Фішинговий лист працівнику", "LEAF", 0.35, "Недостатня обізнаність персоналу", []),
            ("Вхід без другого фактора", "LEAF", 0.9,
             "Відсутність багатофакторної автентифікації", []),
        ]),
        ("Зловживання надлишковими правами", "LEAF", 0.05,
         "Надлишкові права доступу користувачів", []),
    ]),
    2: ("Шифрування робочих станцій бухгалтерії", "OR", None, None, [
        ("Проникнення через RDP", "AND", None, None, [
            ("Пошук відкритого RDP у мережі Інтернет", "LEAF", 0.8, None, []),
            ("Підбір пароля RDP", "LEAF", 0.5, "Відкритий віддалений доступ (RDP)", []),
        ]),
        ("Запуск шкідливого вкладення", "AND", None, None, [
            ("Отримання фішингового листа", "LEAF", 0.7, None, []),
            ("Відкриття вкладення користувачем", "LEAF", 0.4,
             "Недостатня обізнаність персоналу", []),
        ]),
    ]),
}


def _tree(spec, vulns) -> AttackNode:
    name, gate, p, vuln, children = spec
    return AttackNode(name=name, gate=gate, probability=p,
                      vulnerability_id=vulns[vuln].id if vuln else None,
                      children=[_tree(c, vulns) for c in children])


def run() -> None:
    with SessionLocal() as db:
        if db.scalar(select(models.RiskLevel.id).limit(1)) is None:
            raise SystemExit("Довідники порожні: спершу виконайте `alembic upgrade head`.")

        for model in (models.RiskScenario, models.ProtectiveMeasure, models.Threat,
                      models.Asset, models.Vulnerability):
            db.execute(delete(model))

        asset_cats = {c.name: c for c in db.scalars(select(models.AssetCategory))}
        threat_cats = {c.code: c for c in db.scalars(select(models.ThreatCategory))}

        vulns = {}
        for name, cve, cvss, severity in VULNERABILITIES:
            vulns[name] = models.Vulnerability(
                name=name, cve_id=cve, cvss_score=Decimal(cvss) if cvss else None,
                severity=severity)
        assets = {name: models.Asset(name=name, category=asset_cats[cat], owner=owner,
                                     confidentiality=c, integrity=i, availability=a)
                  for name, cat, owner, c, i, a in ASSETS}
        threats = {name: models.Threat(name=name, category=threat_cats[code], base_likelihood=p)
                   for name, code, p in THREATS}
        measures = {name: models.ProtectiveMeasure(
                        name=name, control_ref=ref, measure_type=kind,
                        effectiveness=Decimal(eff), cost=Decimal(cost),
                        vulnerabilities=[vulns[v] for v in closes])
                    for name, ref, kind, eff, cost, closes in MEASURES}
        db.add_all([*vulns.values(), *assets.values(), *threats.values(), *measures.values()])

        scenarios = []
        for asset, threat, vuln, p, i, links in SCENARIOS:
            a, t, v = assets[asset], threats[threat], vulns[vuln]
            if v not in t.vulnerabilities:
                t.vulnerabilities.append(v)
            if v not in a.vulnerabilities:
                a.vulnerabilities.append(v)
            scenario = models.RiskScenario(asset=a, threat=t, vulnerability=v, measure_links=[
                models.ScenarioMeasure(measure=measures[m], status=s) for m, s in links])
            db.add(scenario)
            scenarios.append((scenario, p, i))
        db.flush()

        for index, spec in TREES.items():
            save_tree(db, scenarios[index][0], _tree(spec, vulns))
        for scenario, p, i in scenarios:
            matrix_assessment(db, scenario, p, i)
            combined_assessment(db, scenario)
        db.commit()
    print(f"Активів: {len(ASSETS)}, загроз: {len(THREATS)}, вразливостей: {len(VULNERABILITIES)}, "
          f"заходів: {len(MEASURES)}, сценаріїв: {len(SCENARIOS)}")


if __name__ == "__main__":
    run()
