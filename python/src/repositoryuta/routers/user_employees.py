from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import UserEmployee
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import UserEmployeeCreate, UserEmployeeRead, UserEmployeeUpdate
from repositoryuta.services.crud_service import CrudService

# Espejo de UserEmployeesController.cs: [Authorize] simple, sin restriccion de
# rol. CRUD generico, salvo Create que valida HrEmployeeId (mismo bug ya
# corregido en UsersController.Create: sin esto, el vinculo quedaba con
# HrEmployeeId en 0/NULL y la sesion del usuario nunca recibia employeeId).
router = APIRouter(prefix="/api/user-employees", tags=["user-employees"])


def _service(session: Session) -> CrudService[UserEmployee, UserEmployeeCreate, UserEmployeeUpdate]:
    return CrudService(session, UserEmployee)


@router.get("")
def list_user_employees(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(UserEmployeeRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{user_employee_id}")
def get_user_employee(
    user_employee_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    entity = _service(session).get(user_employee_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserEmployeeRead.model_validate(entity)))


@router.post("")
def create_user_employee(
    dto: UserEmployeeCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    if dto.hr_employee_id <= 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="HrEmployeeId es obligatorio y debe ser un identificador de empleado valido.",
        )
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(UserEmployeeRead.model_validate(result)))


@router.put("/{user_employee_id}")
def update_user_employee(
    user_employee_id: int,
    dto: UserEmployeeUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    updated = _service(session).update(user_employee_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserEmployeeRead.model_validate(updated)))


@router.delete("/{user_employee_id}")
def delete_user_employee(
    user_employee_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    deleted = _service(session).delete(user_employee_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
