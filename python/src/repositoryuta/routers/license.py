from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.license import LicenseAssignEmployeeRequest, LicenseAssignRequest
from repositoryuta.services import license_service

# Espejo de LicenseController.cs. El .NET original solo declara [Authorize]
# (sin roles) pese a que su docstring dice "escritura requiere rol
# Administrador" — esa restriccion nunca fue implementada en el codigo real,
# asi que aqui se replica el comportamiento real (cualquier usuario
# autenticado, incluida la escritura), no el comentario.
router = APIRouter(prefix="/api/licenses", tags=["licenses"])


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail=message)


def _unprocessable(message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=message)


# ── SKUs del tenant ──────────────────────────────────────────────────────────


@router.get("/skus")
def get_skus(_actor_id: UUID = Depends(get_current_user_id)) -> ApiResponse:
    skus = license_service.get_subscribed_skus()
    return ApiResponse.ok([dump(s) for s in skus], f"{len(skus)} SKU(s) encontrados")


# ── Licencias de un usuario ───────────────────────────────────────────────────


@router.get("/users/{upn}")
def get_user_licenses(
    upn: str, _actor_id: UUID = Depends(get_current_user_id)
) -> ApiResponse:
    licenses = license_service.get_user_licenses(upn)
    return ApiResponse.ok(
        [dump(license_) for license_ in licenses],
        f"{len(licenses)} licencia(s) asignadas a {upn}",
    )


# ── Asignación / remoción ─────────────────────────────────────────────────────


@router.post("/assign")
def assign(
    req: LicenseAssignRequest, _actor_id: UUID = Depends(get_current_user_id)
) -> ApiResponse:
    if not req.upn.strip() or not req.sku_part_number.strip():
        raise _bad_request("Upn y SkuPartNumber son requeridos")

    result = license_service.assign_license(req.upn, req.sku_part_number, req.country_code)
    if not result.success:
        raise _unprocessable(result.message or "Error al asignar licencia")
    return ApiResponse.ok(dump(result), result.message)


@router.post("/assign-employee")
def assign_employee(
    req: LicenseAssignEmployeeRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    if not req.upn.strip():
        raise _bad_request("Upn es requerido")

    result = license_service.assign_employee_license(session, req.upn, req.country_code)
    if not result.success:
        raise _unprocessable(result.message or "Error al asignar licencia de empleado")
    return ApiResponse.ok(dump(result), result.message)


@router.post("/remove")
def remove(
    req: LicenseAssignRequest, _actor_id: UUID = Depends(get_current_user_id)
) -> ApiResponse:
    if not req.upn.strip() or not req.sku_part_number.strip():
        raise _bad_request("Upn y SkuPartNumber son requeridos")

    result = license_service.remove_license(req.upn, req.sku_part_number)
    if not result.success:
        raise _unprocessable(result.message or "Error al remover licencia")
    return ApiResponse.ok(dump(result), result.message)


@router.patch("/users/{upn}/usage-location")
def set_usage_location(
    upn: str,
    countryCode: str = Query(default="EC"),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    license_service.set_usage_location(upn, countryCode)
    return ApiResponse.ok(None, f"UsageLocation={countryCode} configurado para {upn}")
