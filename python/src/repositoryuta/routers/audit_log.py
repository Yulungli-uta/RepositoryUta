from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import AuditLog
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import AuditLogCreate, AuditLogRead
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/audit-log", tags=["audit-log"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[AuditLog, AuditLogCreate, AuditLogCreate]:
    return CrudService(session, AuditLog)


@router.get("")
def list_audit_log(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(AuditLogRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{audit_id}")
def get_audit_log(
    audit_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(audit_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(AuditLogRead.model_validate(entity)))


@router.get("/by-module/{module}")
def get_by_module(
    module: str,
    entity_id: str | None = Query(default=None, alias="entityId"),
    user_id: UUID | None = Query(default=None, alias="userId"),
    limit: int = 100,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo de AuditLogController.GetByModule: sin paginacion real, capado a
    `limit` filas (max 500) — el volumen esperado por modulo es bajo."""
    limit = min(max(limit, 1), 500)

    stmt = select(AuditLog).where(AuditLog.module == module)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)

    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit)
    items = list(session.scalars(stmt))
    return ApiResponse.ok([dump(AuditLogRead.model_validate(item)) for item in items])


@router.post("")
def create_audit_log(
    dto: AuditLogCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(AuditLogRead.model_validate(result)))


# Sin PUT/DELETE: el log de auditoria es append-only por diseno (no se edita
# ni se borra) — igual que AuditLogController.cs.
