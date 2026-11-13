"""CRUD для довідників: категорії, ІТ-активи, загрози, вразливості, заходи захисту."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..services import get_or_404, load_many

router = APIRouter(prefix="/api")


def _commit(db: Session):
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409,
                            detail="Порушено обмеження цілісності (дублікат або запис використовується)"
                            ) from exc


def register_crud(path: str, model, schema_in, schema_out, what: str,
                  links: dict[str, tuple[str, type]] | None = None, order_by=None):
    """Реєструє list/get/create/update/delete для довідника.

    links: поле схеми зі списком id -> (атрибут-зв'язок M:N, модель цілі).
    """
    links = links or {}
    order = order_by if order_by is not None else model.id

    def apply(db: Session, obj, payload):
        data = payload.model_dump()
        for field, (attr, target) in links.items():
            setattr(obj, attr, load_many(db, target, data.pop(field), target.__name__))
        if "category_id" in data and data["category_id"] is not None:
            category_model = model.category.property.mapper.class_
            get_or_404(db, category_model, data["category_id"], "Категорію")
        for key, value in data.items():
            setattr(obj, key, value)

    @router.get(f"/{path}", response_model=list[schema_out], name=f"list_{path}")
    def list_items(db: Session = Depends(get_db)):
        return db.scalars(select(model).order_by(order)).all()

    @router.get(f"/{path}/{{item_id}}", response_model=schema_out, name=f"get_{path}")
    def get_item(item_id: int, db: Session = Depends(get_db)):
        return get_or_404(db, model, item_id, what)

    @router.post(f"/{path}", response_model=schema_out, status_code=201, name=f"create_{path}")
    def create_item(payload: schema_in, db: Session = Depends(get_db)):
        obj = model()
        apply(db, obj, payload)
        db.add(obj)
        _commit(db)
        db.refresh(obj)
        return obj

    @router.put(f"/{path}/{{item_id}}", response_model=schema_out, name=f"update_{path}")
    def update_item(item_id: int, payload: schema_in, db: Session = Depends(get_db)):
        obj = get_or_404(db, model, item_id, what)
        apply(db, obj, payload)
        _commit(db)
        db.refresh(obj)
        return obj

    @router.delete(f"/{path}/{{item_id}}", status_code=204, name=f"delete_{path}")
    def delete_item(item_id: int, db: Session = Depends(get_db)):
        db.delete(get_or_404(db, model, item_id, what))
        _commit(db)


register_crud("asset-categories", models.AssetCategory, schemas.AssetCategoryIn,
              schemas.AssetCategoryOut, "Категорію активів", order_by=models.AssetCategory.name)
register_crud("threat-categories", models.ThreatCategory, schemas.ThreatCategoryIn,
              schemas.ThreatCategoryOut, "Категорію загроз")
register_crud("assets", models.Asset, schemas.AssetIn, schemas.AssetOut, "ІТ-актив",
              links={"vulnerability_ids": ("vulnerabilities", models.Vulnerability)},
              order_by=models.Asset.name)
register_crud("threats", models.Threat, schemas.ThreatIn, schemas.ThreatOut, "Загрозу",
              links={"vulnerability_ids": ("vulnerabilities", models.Vulnerability)},
              order_by=models.Threat.name)
register_crud("vulnerabilities", models.Vulnerability, schemas.VulnerabilityIn,
              schemas.VulnerabilityOut, "Вразливість", order_by=models.Vulnerability.name)
register_crud("measures", models.ProtectiveMeasure, schemas.MeasureIn, schemas.MeasureOut,
              "Захід захисту",
              links={"vulnerability_ids": ("vulnerabilities", models.Vulnerability)},
              order_by=models.ProtectiveMeasure.name)


@router.get("/risk-levels", response_model=list[schemas.RiskLevelOut])
def list_risk_levels(db: Session = Depends(get_db)):
    return db.scalars(select(models.RiskLevel).order_by(models.RiskLevel.min_score)).all()
