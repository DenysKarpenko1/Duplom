"""API довідників, зв'язків M:N, сценаріїв та сумісного /api/risks."""


def _catalog(client):
    cat = client.get("/api/asset-categories").json()[0]["id"]
    tcat = client.get("/api/threat-categories").json()[0]["id"]
    v1 = client.post("/api/vulnerabilities", json={
        "name": "Невиправлена вразливість", "cve_id": "CVE-2024-4577", "cvss_score": 9.8,
        "severity": 5}).json()
    v2 = client.post("/api/vulnerabilities", json={"name": "Немає MFA"}).json()
    asset = client.post("/api/assets", json={
        "name": "БД клієнтів", "category_id": cat, "confidentiality": 5,
        "vulnerability_ids": [v1["id"], v2["id"]]}).json()
    threat = client.post("/api/threats", json={
        "name": "Несанкціонований доступ", "category_id": tcat, "base_likelihood": 4,
        "vulnerability_ids": [v1["id"], v2["id"]]}).json()
    measure = client.post("/api/measures", json={
        "name": "MFA", "measure_type": "preventive", "effectiveness": 0.85,
        "control_ref": "ISO 27001 A.8.5", "vulnerability_ids": [v2["id"]]}).json()
    return asset, threat, v1, v2, measure


def test_reference_data_seeded_by_migration(client):
    levels = client.get("/api/risk-levels").json()
    assert [(lv["name"], lv["min_score"], lv["max_score"]) for lv in levels] == [
        ("Низький", 1, 4), ("Середній", 5, 9), ("Високий", 10, 14), ("Критичний", 15, 25)]
    codes = {c["code"] for c in client.get("/api/threat-categories").json()}
    assert codes == {"adversarial", "accidental", "structural", "environmental"}


def test_many_to_many_links(client):
    asset, threat, v1, v2, measure = _catalog(client)
    assert {v["id"] for v in threat["vulnerabilities"]} == {v1["id"], v2["id"]}
    assert asset["category"]["name"]

    vuln = client.get(f"/api/vulnerabilities/{v2['id']}").json()
    assert [t["name"] for t in vuln["threats"]] == ["Несанкціонований доступ"]
    assert [a["name"] for a in vuln["assets"]] == ["БД клієнтів"]
    assert [m["name"] for m in vuln["measures"]] == ["MFA"]
    assert measure["effectiveness"] == 0.85

    # оновлення замінює набір зв'язків
    upd = client.put(f"/api/threats/{threat['id']}", json={
        "name": threat["name"], "vulnerability_ids": [v1["id"]]}).json()
    assert [v["id"] for v in upd["vulnerabilities"]] == [v1["id"]]

    # видалення вразливості каскадно прибирає зв'язки
    assert client.delete(f"/api/vulnerabilities/{v1['id']}").status_code == 204
    assert client.get(f"/api/threats/{threat['id']}").json()["vulnerabilities"] == []


def test_validation_and_integrity(client):
    asset, threat, v1, *_ = _catalog(client)
    assert client.post("/api/assets", json={"name": "БД клієнтів"}).status_code == 409
    assert client.post("/api/assets", json={"name": "X", "integrity": 6}).status_code == 422
    assert client.post("/api/threats", json={
        "name": "Y", "vulnerability_ids": [999]}).status_code == 422
    assert client.post("/api/assets", json={"name": "Z", "category_id": 999}).status_code == 404
    assert client.post("/api/measures", json={
        "name": "W", "measure_type": "magic"}).status_code == 422
    assert client.get("/api/assets/999").status_code == 404


def test_scenario_assessments_history(client):
    asset, threat, v1, v2, measure = _catalog(client)
    body = {"asset_id": asset["id"], "threat_id": threat["id"], "vulnerability_id": v1["id"],
            "measures": [{"measure_id": measure["id"], "status": "implemented"}]}
    scenario = client.post("/api/scenarios", json=body).json()
    assert scenario["measure_links"] == [
        {"measure": {"id": measure["id"], "name": "MFA"}, "status": "implemented"}]
    assert client.post("/api/scenarios", json=body).status_code == 409

    url = f"/api/scenarios/{scenario['id']}/assessments"
    first = client.post(url, json={"probability": 4, "impact": 5}).json()
    assert (first["score"], first["level"]["name"], first["method"]) == (20, "Критичний", "matrix")
    client.post(url, json={"probability": 2, "impact": 5})
    history = client.get(url).json()
    assert [a["score"] for a in history] == [20, 10]

    # актив, задіяний у сценарії, видалити не можна (RESTRICT)
    assert client.delete(f"/api/assets/{asset['id']}").status_code == 409
    assert client.delete(f"/api/scenarios/{scenario['id']}").status_code == 204
    assert client.delete(f"/api/assets/{asset['id']}").status_code == 204


def test_legacy_risks_api(client):
    payload = {"asset": "Поштовий сервер", "threat": "Фішинг",
               "vulnerability": "Немає MFA", "probability": 3, "impact": 3}
    created = client.post("/api/risks", json=payload)
    assert created.status_code == 201
    assert (created.json()["score"], created.json()["level"]) == (9, "Середній")

    # той самий сценарій -> нова оцінка, а не дублікат у довідниках
    client.post("/api/risks", json={**payload, "probability": 5})
    client.post("/api/risks", json={"asset": "Вебпортал", "threat": "DDoS",
                                    "vulnerability": "Немає захисту", "probability": 1,
                                    "impact": 2})
    risks = client.get("/api/risks").json()
    assert [(r["asset"], r["score"]) for r in risks] == [("Поштовий сервер", 15), ("Вебпортал", 2)]
    assert len(client.get("/api/assets").json()) == 2
    sid = risks[0]["id"]
    assert len(client.get(f"/api/scenarios/{sid}/assessments").json()) == 2

    assert client.delete(f"/api/risks/{sid}").status_code == 204
    assert len(client.get("/api/risks").json()) == 1
    assert client.delete("/api/risks/999").status_code == 404


def test_seed(session_factory, monkeypatch, client):
    from app import seed
    monkeypatch.setattr(seed, "SessionLocal", session_factory)
    seed.run()
    seed.run()  # повторний запуск не дублює дані
    assert len(client.get("/api/scenarios").json()) == len(seed.SCENARIOS)
    assert len(client.get("/api/risks").json()) == len(seed.SCENARIOS)
    assert len(client.get("/api/measures").json()) == len(seed.MEASURES)
