"""Розширений тестовий набір даних умовного підприємства для експерименту.

    alembic upgrade head
    python -m app.seed_enterprise

Умовне підприємство — ТОВ «Альфа-Сервіс» (≈150 працівників, онлайн-продажі,
власний вебпортал, бухгалтерія, склад). Набір містить:
  * класифіковані ІТ-активи з цінністю C/I/A;
  * загрози всіх чотирьох типів джерел NIST SP 800-30;
  * вразливості (частина — з CVE/CVSS) та заходи захисту з ефективністю;
  * сценарії ризику, кожен — з деревом атак, побудованим за шаблоном загрози;
  * шість щомісячних раундів оцінювання (червень–листопад 2026), між якими
    поступово впроваджуються заходи, — для графіків динаміки.

Обидві моделі отримують однакові вихідні дані:
  * матрична: P = ⌈(базова ймовірність загрози + критичність вразливості) / 2⌉,
    I = max(C, I, A) активу, залишковий ризик — через сумарну ефективність заходів;
  * комбінована: P — з дерева атак, I — так само, R — нечіткий висновок.

Генерація детермінована (фіксоване зерно), тому результати відтворювані.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import delete, select

from . import models
from .assessment import combined_assessment, matrix_assessment, save_tree
from .core.attack_tree import AttackNode
from .database import SessionLocal
from .risk_core import matrix_probability

SEED = 2026
ROUND_DATES = [datetime(2026, m, 1, 10, 0, tzinfo=timezone.utc) for m in range(6, 12)]

# ---------------------------------------------------------------------------
# ІТ-активи: назва, категорія, власник, C, I, A
# ---------------------------------------------------------------------------
ASSETS = [
    ("CRM-система та база клієнтів", "Інформація", "Комерційний відділ", 5, 5, 4),
    ("Інтернет-магазин", "Програмне забезпечення", "ІТ-відділ", 3, 4, 5),
    ("Платіжний шлюз", "Сервіси", "Фінансовий відділ", 5, 5, 5),
    ("ERP-система (облік, склад)", "Програмне забезпечення", "Фінансовий відділ", 4, 5, 4),
    ("База даних бухгалтерії", "Інформація", "Бухгалтерія", 5, 5, 3),
    ("Робочі станції бухгалтерії", "Апаратне забезпечення", "Бухгалтерія", 4, 4, 3),
    ("Робочі станції офісу", "Апаратне забезпечення", "ІТ-відділ", 3, 3, 3),
    ("Ноутбуки керівництва", "Апаратне забезпечення", "Адміністрація", 5, 3, 2),
    ("Корпоративна пошта", "Сервіси", "ІТ-відділ", 4, 3, 4),
    ("Файловий сервер", "Інформація", "ІТ-відділ", 4, 4, 3),
    ("Сервер резервного копіювання", "Апаратне забезпечення", "ІТ-відділ", 4, 5, 4),
    ("Контролер домену (AD)", "Програмне забезпечення", "ІТ-відділ", 5, 5, 5),
    ("Периметровий міжмережевий екран", "Мережа", "ІТ-відділ", 3, 5, 5),
    ("Корпоративна Wi-Fi мережа", "Мережа", "ІТ-відділ", 3, 3, 3),
    ("Серверна кімната", "Апаратне забезпечення", "Адміністрація", 3, 4, 5),
    ("Кадрові дані працівників", "Інформація", "Відділ кадрів", 5, 4, 2),
    ("Система відеоспостереження", "Сервіси", "Служба безпеки", 2, 3, 3),
    ("Адміністратори ІТ", "Персонал", "ІТ-відділ", 4, 4, 4),
]

# ---------------------------------------------------------------------------
# Вразливості: ключ -> (назва, CVE, CVSS, критичність 1..5)
# ---------------------------------------------------------------------------
VULNS = {
    "web_cve": ("Невиправлена RCE-вразливість вебсервера", "CVE-2024-4577", "9.8", 5),
    "input": ("Недостатня перевірка вхідних даних", None, None, 4),
    "patch": ("Запізнення встановлення оновлень ОС", None, None, 4),
    "rdp": ("Відкритий віддалений доступ (RDP)", None, None, 4),
    "awareness": ("Недостатня обізнаність персоналу", None, None, 3),
    "no_mfa": ("Відсутність багатофакторної автентифікації", None, None, 4),
    "weak_pwd": ("Слабка парольна політика", None, None, 3),
    "rights": ("Надлишкові права доступу користувачів", None, None, 3),
    "no_dlp": ("Відсутність контролю витоку даних (DLP)", None, None, 3),
    "no_ddos": ("Відсутність захисту від DDoS", None, None, 4),
    "no_waf": ("Відсутність WAF", None, None, 3),
    "no_raid": ("Відсутність резервування дисків", None, None, 3),
    "no_backup_test": ("Неперевірене відновлення з резервних копій", None, None, 3),
    "change_ctrl": ("Відсутність процедури контролю змін", None, None, 2),
    "no_encrypt": ("Відсутність шифрування дисків ноутбуків", None, None, 4),
    "wpa": ("Застарілий протокол захисту Wi-Fi (WPA2-PSK)", None, None, 3),
    "no_ups": ("Відсутність джерела безперебійного живлення", None, None, 3),
    "no_fire": ("Відсутність автоматичного пожежогасіння", None, None, 2),
    "ad_cve": ("Невиправлена вразливість контролера домену", "CVE-2020-1472", "10.0", 5),
    "vendor": ("Неконтрольований доступ підрядників", None, None, 3),
    "phys": ("Слабкий фізичний контроль доступу", None, None, 2),
    "logging": ("Відсутність централізованого журналювання", None, None, 2),
    "cam_cve": ("Вразливе вбудоване ПЗ IP-камер", "CVE-2021-36260", "9.8", 5),
}

# ---------------------------------------------------------------------------
# Заходи захисту: назва, контроль, тип, ефективність, вартість, вразливості, раунд впровадження
# (None — лише заплановано)
# ---------------------------------------------------------------------------
MEASURES = [
    ("Регулярне встановлення оновлень", "ISO 27001 A.8.8", "preventive", "0.80", 15000,
     ["web_cve", "patch", "ad_cve", "cam_cve"], 1),
    ("Web Application Firewall", "NIST 800-53 SC-7", "preventive", "0.70", 60000,
     ["web_cve", "input", "no_waf"], 3),
    ("Безпечна розробка та код-рев'ю", "ISO 27001 A.8.28", "preventive", "0.60", 40000,
     ["input"], None),
    ("Сервіс захисту від DDoS", "NIST 800-53 SC-5", "preventive", "0.75", 48000, ["no_ddos"], 4),
    ("VPN з MFA для віддаленого доступу", "ISO 27001 A.8.5", "preventive", "0.85", 25000,
     ["rdp", "no_mfa"], 2),
    ("Навчання з кібергігієни та фішинг-симуляції", "ISO 27001 A.6.3", "preventive", "0.50",
     10000, ["awareness"], 2),
    ("Парольна політика та менеджер паролів", "ISO 27001 A.5.17", "preventive", "0.60", 6000,
     ["weak_pwd"], 1),
    ("Рольова модель доступу та перегляд прав", "ISO 27001 A.5.15", "preventive", "0.65", 8000,
     ["rights", "vendor"], 3),
    ("DLP-система", "NIST 800-53 SC-7(10)", "detective", "0.55", 70000, ["no_dlp"], None),
    ("Моніторинг подій безпеки (SIEM)", "NIST 800-53 SI-4", "detective", "0.45", 90000,
     ["logging", "rights", "vendor"], 5),
    ("RAID та резервне копіювання 3-2-1", "ISO 27001 A.8.13", "corrective", "0.90", 30000,
     ["no_raid", "no_backup_test"], 0),
    ("Регламент управління змінами", "ISO 27001 A.8.32", "preventive", "0.60", 3000,
     ["change_ctrl"], 4),
    ("Шифрування дисків (BitLocker)", "ISO 27001 A.8.24", "preventive", "0.90", 5000,
     ["no_encrypt"], 1),
    ("WPA3-Enterprise з RADIUS", "NIST 800-53 AC-18", "preventive", "0.80", 12000, ["wpa"], 5),
    ("ДБЖ і генератор", "ISO 27001 A.7.11", "preventive", "0.85", 55000, ["no_ups"], 3),
    ("Система газового пожежогасіння", "ISO 27001 A.7.5", "corrective", "0.80", 120000,
     ["no_fire"], None),
    ("СКУД та журнал відвідувань", "ISO 27001 A.7.2", "preventive", "0.70", 35000, ["phys"], 2),
    ("Сегментація мережі IoT-пристроїв", "NIST 800-53 SC-7", "preventive", "0.75", 9000,
     ["cam_cve"], 4),
]

# ---------------------------------------------------------------------------
# Загрози та шаблони дерев атак.
# Вузол: ("назва", "AND"|"OR", [діти]) або листок ("назва", p, ключ_вразливості|None)
# main — основна вразливість сценарію; assets — активи, до яких застосовна загроза
# ---------------------------------------------------------------------------
THREATS = [
    {
        "name": "Віддалене виконання коду на вебсервері", "cat": "adversarial", "p": 4,
        "main": "web_cve",
        "assets": ["Інтернет-магазин", "Платіжний шлюз", "CRM-система та база клієнтів"],
        "tree": ("Компрометація вебсервера", "OR", [
            ("Експлуатація відомої CVE", "AND", [
                ("Автоматизоване сканування", 0.95, None),
                ("Експлуатація RCE", 0.9, "web_cve")]),
            ("Атака на вебзастосунок", "AND", [
                ("Пошук вразливого параметра", 0.6, "input"),
                ("Обхід фільтрації запитів", 0.7, "no_waf")]),
        ]),
    },
    {
        "name": "SQL-ін'єкція", "cat": "adversarial", "p": 3, "main": "input",
        "assets": ["Інтернет-магазин", "CRM-система та база клієнтів"],
        "tree": ("Витяг даних через SQL-ін'єкцію", "AND", [
            ("Пошук вразливої форми", 0.7, None),
            ("Обхід WAF", 0.6, "no_waf"),
            ("Експлуатація ін'єкції", 0.55, "input")]),
    },
    {
        "name": "Атака на відмову в обслуговуванні (DDoS)", "cat": "adversarial", "p": 3,
        "main": "no_ddos", "assets": ["Інтернет-магазин", "Платіжний шлюз"],
        "tree": ("Недоступність сервісу", "AND", [
            ("Мотивований зловмисник / вимагання", 0.5, None),
            ("Успішна атака", "OR", [
                ("Об'ємна атака на канал", 0.85, "no_ddos"),
                ("Атака прикладного рівня", 0.5, "no_waf")])]),
    },
    {
        "name": "Зараження програмою-вимагачем", "cat": "adversarial", "p": 4, "main": "rdp",
        "assets": ["Робочі станції бухгалтерії", "Файловий сервер", "ERP-система (облік, склад)",
                   "Робочі станції офісу"],
        "tree": ("Шифрування даних вимагачем", "AND", [
            ("Початковий доступ", "OR", [
                ("Через RDP", "AND", [
                    ("Пошук відкритого RDP", 0.8, None),
                    ("Підбір пароля", 0.5, "weak_pwd"),
                    ("Вхід без другого фактора", 0.9, "rdp")]),
                ("Через фішинг", "AND", [
                    ("Отримання листа", 0.8, None),
                    ("Запуск вкладення", 0.35, "awareness")]),
                ("Через невиправлену вразливість", 0.25, "patch")]),
            ("Відсутність працездатної копії", 0.6, "no_backup_test")]),
    },
    {
        "name": "Компрометація облікових записів (фішинг)", "cat": "adversarial", "p": 4,
        "main": "no_mfa", "assets": ["Корпоративна пошта", "CRM-система та база клієнтів",
                                      "ERP-система (облік, склад)"],
        "tree": ("Вхід під чужим обліковим записом", "AND", [
            ("Викрадення пароля", "OR", [
                ("Фішинговий сайт", 0.35, "awareness"),
                ("Підбір / повторне використання", 0.3, "weak_pwd")]),
            ("Відсутність другого фактора", 0.95, "no_mfa")]),
    },
    {
        "name": "Захоплення контролера домену", "cat": "adversarial", "p": 3, "main": "ad_cve",
        "assets": ["Контролер домену (AD)"],
        "tree": ("Права адміністратора домену", "AND", [
            ("Доступ до внутрішньої мережі", "OR", [
                ("Скомпрометована робоча станція", 0.4, "awareness"),
                ("Підключення через Wi-Fi", 0.3, "wpa"),
                ("Доступ підрядника", 0.25, "vendor")]),
            ("Підвищення привілеїв", "OR", [
                ("Експлуатація Zerologon", 0.9, "ad_cve"),
                ("Викрадення облікових даних адміністратора", 0.3, "rights")])]),
    },
    {
        "name": "Витік даних через дії інсайдера", "cat": "adversarial", "p": 2, "main": "rights",
        "assets": ["CRM-система та база клієнтів", "Кадрові дані працівників", "Файловий сервер",
                   "База даних бухгалтерії"],
        "tree": ("Несанкціоноване винесення даних", "AND", [
            ("Доступ до даних", 0.7, "rights"),
            ("Канал винесення", "OR", [
                ("Знімний носій / хмара", 0.6, "no_dlp"),
                ("Пересилання поштою", 0.4, "no_dlp")]),
            ("Відсутність виявлення", 0.8, "logging")]),
    },
    {
        "name": "Крадіжка або втрата ноутбука", "cat": "accidental", "p": 3, "main": "no_encrypt",
        "assets": ["Ноутбуки керівництва"],
        "tree": ("Розкриття даних з ноутбука", "AND", [
            ("Втрата чи крадіжка пристрою", 0.3, None),
            ("Читання незашифрованого диска", 0.95, "no_encrypt")]),
    },
    {
        "name": "Несанкціоноване підключення до Wi-Fi", "cat": "adversarial", "p": 3, "main": "wpa",
        "assets": ["Корпоративна Wi-Fi мережа"],
        "tree": ("Доступ до корпоративної мережі", "OR", [
            ("Підбір PSK-ключа", 0.4, "wpa"),
            ("Ключ, переданий стороннім", 0.3, "awareness")]),
    },
    {
        "name": "Відмова обладнання", "cat": "structural", "p": 2, "main": "no_raid",
        "assets": ["Файловий сервер", "Сервер резервного копіювання", "База даних бухгалтерії"],
        "tree": ("Втрата даних через відмову", "AND", [
            ("Відмова диска", 0.3, None),
            ("Відсутність резервування", 0.9, "no_raid"),
            ("Невдале відновлення з копії", 0.5, "no_backup_test")]),
    },
    {
        "name": "Помилка адміністратора під час змін", "cat": "accidental", "p": 3,
        "main": "change_ctrl",
        "assets": ["ERP-система (облік, склад)", "Периметровий міжмережевий екран",
                   "Контролер домену (AD)"],
        "tree": ("Збій через помилкову зміну", "AND", [
            ("Помилкова зміна конфігурації", 0.3, "change_ctrl"),
            ("Відсутність відкату", 0.5, "no_backup_test")]),
    },
    {
        "name": "Перебої енергопостачання", "cat": "environmental", "p": 4, "main": "no_ups",
        "assets": ["Серверна кімната"],
        "tree": ("Аварійне вимкнення серверів", "AND", [
            ("Відключення електроенергії", 0.7, None),
            ("Відсутність резервного живлення", 0.9, "no_ups")]),
    },
    {
        "name": "Пожежа в серверній", "cat": "environmental", "p": 1, "main": "no_fire",
        "assets": ["Серверна кімната"],
        "tree": ("Знищення обладнання вогнем", "AND", [
            ("Займання", 0.03, None),
            ("Поширення без гасіння", 0.9, "no_fire")]),
    },
    {
        "name": "Несанкціонований фізичний доступ", "cat": "adversarial", "p": 2, "main": "phys",
        "assets": ["Серверна кімната", "Робочі станції бухгалтерії"],
        "tree": ("Фізичний доступ до обладнання", "OR", [
            ("Проходження без пропуску", 0.3, "phys"),
            ("Соціальна інженерія на рецепції", 0.25, "awareness")]),
    },
    {
        "name": "Компрометація IP-камер (ботнет)", "cat": "adversarial", "p": 4, "main": "cam_cve",
        "assets": ["Система відеоспостереження"],
        "tree": ("Захоплення камер", "OR", [
            ("Експлуатація вбудованого ПЗ", 0.9, "cam_cve"),
            ("Стандартні паролі", 0.5, "weak_pwd")]),
    },
    {
        "name": "Атака через підрядника", "cat": "adversarial", "p": 2, "main": "vendor",
        "assets": ["ERP-система (облік, склад)", "Платіжний шлюз"],
        "tree": ("Компрометація через ланцюг постачання", "AND", [
            ("Компрометація підрядника", 0.2, None),
            ("Доступ підрядника без обмежень", 0.8, "vendor"),
            ("Відсутність моніторингу дій", 0.8, "logging")]),
    },
    {
        "name": "Соціальна інженерія щодо адміністратора", "cat": "adversarial", "p": 3,
        "main": "awareness", "assets": ["Адміністратори ІТ"],
        "tree": ("Розкриття облікових даних адміністратора", "AND", [
            ("Цільовий фішинг", 0.5, None),
            ("Довіра до шахрая", 0.3, "awareness"),
            ("Вхід без другого фактора", 0.9, "no_mfa")]),
    },
]


def _jitter(rng: random.Random, p: float) -> float:
    """Невелике випадкове відхилення ймовірності листка (індивідуальність активу)."""
    return round(min(0.99, max(0.01, p * rng.uniform(0.85, 1.15))), 3)


def _build(spec, vulns, rng) -> AttackNode:
    if isinstance(spec[1], str):
        name, gate, children = spec
        return AttackNode(name=name, gate=gate, children=[_build(c, vulns, rng) for c in children])
    name, p, vkey = spec
    return AttackNode(name=name, probability=_jitter(rng, p),
                      vulnerability_id=vulns[vkey].id if vkey else None)


def _tree_vulns(spec) -> set[str]:
    if isinstance(spec[1], str):
        return set().union(*(_tree_vulns(c) for c in spec[2]))
    return {spec[2]} if spec[2] else set()


def run(rounds: int = len(ROUND_DATES)) -> dict:
    rng = random.Random(SEED)
    with SessionLocal() as db:
        if db.scalar(select(models.RiskLevel.id).limit(1)) is None:
            raise SystemExit("Довідники порожні: спершу виконайте `alembic upgrade head`.")
        for model in (models.RiskScenario, models.ProtectiveMeasure, models.Threat,
                      models.Asset, models.Vulnerability):
            db.execute(delete(model))

        asset_cats = {c.name: c for c in db.scalars(select(models.AssetCategory))}
        threat_cats = {c.code: c for c in db.scalars(select(models.ThreatCategory))}

        vulns = {k: models.Vulnerability(name=n, cve_id=cve,
                                         cvss_score=Decimal(cvss) if cvss else None, severity=s)
                 for k, (n, cve, cvss, s) in VULNS.items()}
        assets = {n: models.Asset(name=n, category=asset_cats[c], owner=o, confidentiality=ci,
                                  integrity=ii, availability=ai,
                                  created_at=ROUND_DATES[0])
                  for n, c, o, ci, ii, ai in ASSETS}
        measures = []
        for name, ref, kind, eff, cost, closes, rnd in MEASURES:
            m = models.ProtectiveMeasure(name=name, control_ref=ref, measure_type=kind,
                                         effectiveness=Decimal(eff), cost=Decimal(cost),
                                         vulnerabilities=[vulns[v] for v in closes])
            measures.append((m, set(closes), rnd))
        threats = {}
        for t in THREATS:
            keys = _tree_vulns(t["tree"])
            threats[t["name"]] = models.Threat(
                name=t["name"], category=threat_cats[t["cat"]], base_likelihood=t["p"],
                vulnerabilities=[vulns[k] for k in sorted(keys)])
        db.add_all([*vulns.values(), *assets.values(), *threats.values(),
                    *(m for m, _, _ in measures)])
        db.flush()

        scenarios = []  # (сценарій, вразливості дерева, P матриці)
        for t in THREATS:
            keys = _tree_vulns(t["tree"])
            main = vulns[t["main"]]
            for asset_name in t["assets"]:
                asset = assets[asset_name]
                for k in keys:
                    if vulns[k] not in asset.vulnerabilities:
                        asset.vulnerabilities.append(vulns[k])
                scenario = models.RiskScenario(
                    asset=asset, threat=threats[t["name"]], vulnerability=main,
                    created_at=ROUND_DATES[0],
                    description=f"Шаблон дерева: «{t['tree'][0]}»")
                db.add(scenario)
                db.flush()
                save_tree(db, scenario, _build(t["tree"], vulns, rng))
                # заходи, що закривають вразливості дерева, — спершу лише заплановані
                scenario.measure_links = [
                    models.ScenarioMeasure(measure=m, status="planned")
                    for m, closes, _ in measures if closes & keys]
                p_matrix = matrix_probability(t["p"], main.severity)
                scenarios.append((scenario, p_matrix))
        db.flush()

        # Щомісячні раунди: впровадження заходів і оцінювання обома методами
        count = 0
        for r, date in enumerate(ROUND_DATES[:rounds]):
            for scenario, p_matrix in scenarios:
                for link in scenario.measure_links:
                    rnd = next(x for m, _, x in measures if m is link.measure)
                    link.status = "implemented" if rnd is not None and rnd <= r else "planned"
                db.flush()
                impact = max(scenario.asset.confidentiality, scenario.asset.integrity,
                             scenario.asset.availability)
                a1 = matrix_assessment(db, scenario, p_matrix, impact, notes=f"Раунд {r + 1}")
                a2 = combined_assessment(db, scenario)
                a2.notes = f"Раунд {r + 1}. {a2.notes}"
                a1.assessed_at = a2.assessed_at = date
                count += 2
        db.commit()
        summary = {"assets": len(ASSETS), "threats": len(THREATS), "vulnerabilities": len(VULNS),
                   "measures": len(MEASURES), "scenarios": len(scenarios),
                   "rounds": min(rounds, len(ROUND_DATES)), "assessments": count}
    print("Набір даних «ТОВ Альфа-Сервіс»: " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    return summary


if __name__ == "__main__":
    run()
