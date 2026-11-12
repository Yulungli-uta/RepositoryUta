from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.provisioning import (
    DisableEmployeeResultRead,
    ProvisionEmployeeRequest,
    RetryProvisioningRequest,
)
from repositoryuta.services import provisioning_service

# Espejo de ProvisioningController.cs.
router = APIRouter(prefix="/api/provisioning", tags=["provisioning"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail=message)


def _not_found(message: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=message)


def _disable_response(result: DisableEmployeeResultRead) -> ApiResponse:
    if result.success:
        return ApiResponse.ok(dump(result), "Cuenta institucional deshabilitada.")
    raise _bad_request(result.error_message or "Error al deshabilitar la cuenta.")


# ── Creación ──────────────────────────────────────────────────────────────────


@router.post("/employees")
def provision(
    req: ProvisionEmployeeRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    if not req.display_name.strip() or not req.given_name.strip() or not req.surname.strip():
        raise _bad_request("DisplayName, GivenName y Surname son requeridos")
    if not req.initial_password.strip():
        raise _bad_request("InitialPassword es requerida para crear el usuario en AD")
    if req.hr_employee_id <= 0:
        raise _bad_request("HrEmployeeId debe ser un valor positivo")

    result = provisioning_service.provision(session, req)
    return ApiResponse.ok(
        dump(result), "Aprovisionamiento iniciado. Verifique el estado de sincronización con Entra."
    )


@router.post("/employees/bulk")
def provision_bulk(
    requests: list[ProvisionEmployeeRequest],
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    if not requests:
        raise _bad_request("Se requiere al menos un empleado en el lote")
    if len(requests) > 200:
        raise _bad_request("El lote no puede superar 200 empleados por solicitud")

    results = provisioning_service.provision_bulk(session, requests)
    ok = sum(1 for r in results if r.success)
    failed = len(results) - ok
    return ApiResponse.ok(
        [dump(r) for r in results],
        f"Lote procesado: {ok} exitosos, {failed} fallidos de {len(results)} total",
    )


# ── Consulta ──────────────────────────────────────────────────────────────────


@router.get("/employees/{provisioning_id}")
def get_status(
    provisioning_id: UUID, session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = provisioning_service.get_status(session, provisioning_id)
    if result is None:
        raise _not_found(f"Aprovisionamiento '{provisioning_id}' no encontrado")
    return ApiResponse.ok(dump(result))


@router.get("/employees")
def list_provisioning(
    page: int = 1,
    pageSize: int = 50,
    statusId: int | None = None,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    if page < 1:
        page = 1
    if pageSize < 1 or pageSize > 200:
        pageSize = 50

    result = provisioning_service.list_provisioning(session, page, pageSize, statusId)
    return ApiResponse.ok(
        {
            "items": [dump(item) for item in result.items],
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
            "totalPages": (result.total_count + result.page_size - 1) // result.page_size
            if result.page_size
            else 0,
            "hasPreviousPage": result.page > 1,
            "hasNextPage": result.page * result.page_size < result.total_count,
        }
    )


# ── Acciones ──────────────────────────────────────────────────────────────────


@router.patch("/employees/{provisioning_id}/retry")
def retry(
    provisioning_id: UUID,
    req: RetryProvisioningRequest | None = Body(default=None),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        result = provisioning_service.retry(
            session, provisioning_id, req.initial_password if req else None
        )
    except ValueError as exc:
        raise _bad_request(str(exc)) from exc

    if result is None:
        raise _not_found(f"Aprovisionamiento '{provisioning_id}' no encontrado")
    return ApiResponse.ok(dump(result), "Reintento ejecutado")


# ── Completado (Entra sync → licencia) ───────────────────────────────────────


@router.post("/employees/{provisioning_id}/complete")
def complete(
    provisioning_id: UUID, session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = provisioning_service.check_and_complete_provisioning(session, provisioning_id)
    if result is None:
        raise _not_found(f"Aprovisionamiento '{provisioning_id}' no encontrado")
    return ApiResponse.ok(dump(result), f"Estado actualizado: {result.provisioning_status_name}")


@router.post("/employees/complete-pending")
def complete_pending(
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = provisioning_service.complete_pending(session)
    return ApiResponse.ok(
        dump(result),
        f"Procesados: {result.total_processed} — "
        f"Licencias asignadas: {result.license_assigned} — "
        f"Aún pendientes: {result.still_pending} — "
        f"Fallidos: {result.failed}",
    )


# ── Restablecimiento de contraseña ───────────────────────────────────────────


@router.post("/employees/{provisioning_id}/reset-password")
def reset_password(
    provisioning_id: UUID, session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        result = provisioning_service.reset_password(session, provisioning_id)
    except ValueError as exc:
        raise _bad_request(str(exc)) from exc

    if result is None:
        raise _not_found(f"Aprovisionamiento '{provisioning_id}' no encontrado")
    return ApiResponse.ok(
        dump(result),
        "Contraseña restablecida. Entregue las credenciales al empleado de forma segura.",
    )


# ── Deshabilitar cuenta ───────────────────────────────────────────────────────


@router.post("/employees/by-ad-id/{ad_object_id}/disable")
def disable_by_ad_object_id(
    ad_object_id: str, session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = provisioning_service.disable_by_ad_id(session, ad_object_id)
    if result is None:
        raise _not_found(f"Sin registro de aprovisionamiento para el objeto AD '{ad_object_id}'.")
    return _disable_response(result)


@router.post("/employees/{identifier}/disable")
def disable_employee_by_identifier(
    identifier: str, session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo combinado de DisableEmployee({hrEmployeeId:int}) y
    DisableByProvisioningId({id:guid}): ASP.NET distingue esas dos rutas por
    restricción de tipo en el mismo segmento; FastAPI no soporta dos rutas con
    la misma forma literal distinguidas solo por el tipo del parámetro, así que
    aquí se hace el mismo despacho a mano (numérico → HrEmployeeId, GUID → Id)."""
    try:
        hr_employee_id = int(identifier)
    except ValueError:
        hr_employee_id = None

    if hr_employee_id is not None:
        return _disable_response(provisioning_service.disable_employee(session, hr_employee_id))

    try:
        provisioning_id = UUID(identifier)
    except ValueError as exc:
        raise _not_found(f"Aprovisionamiento '{identifier}' no encontrado.") from exc

    result = provisioning_service.disable_by_provisioning_id(session, provisioning_id)
    if result is None:
        raise _not_found(f"Aprovisionamiento '{provisioning_id}' no encontrado.")
    return _disable_response(result)
