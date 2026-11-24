from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.provisioning import (
    CreateStudentAdAccountRequest,
    CreateStudentAdAccountResultRead,
    DisableStudentAdAccountResultRead,
)
from repositoryuta.services import student_provisioning_service

# Espejo de StudentProvisioningController.cs. Nota de fidelidad: a diferencia
# de TODOS los demas controllers de este proyecto, este NO usa ApiResponse —
# responde {"data": ...} (200) en exito y {"error": ..., "data": ...} (400) en
# fallo. Se replica tal cual, no es un error de esta migracion.
router = APIRouter(prefix="/api/academic/student-provisioning", tags=["student-provisioning"])

_ADMIN_ROLES = ("Administrador",)


def _response(result: CreateStudentAdAccountResultRead | DisableStudentAdAccountResultRead):
    if result.success:
        return {"data": dump(result)}
    return JSONResponse(
        status_code=400, content={"error": result.error_message, "data": dump(result)}
    )


@router.post("/students")
def create_ad_account(
    req: CreateStudentAdAccountRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
):
    result = student_provisioning_service.create_ad_account(session, req)
    return _response(result)


@router.post("/ad-accounts/{ad_object_id}/disable")
def disable_ad_account(ad_object_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))):
    result = student_provisioning_service.disable_ad_account(ad_object_id)
    return _response(result)
