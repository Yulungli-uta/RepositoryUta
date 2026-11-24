import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from repositoryuta.core.pagination import PagedRequest
from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import User
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import UserCreate, UserEmployeeRead, UserRead, UserUpdate
from repositoryuta.services import user_permission_service
from repositoryuta.services.crud_service import CrudService
from repositoryuta.services.user_registration_service import create_user_with_employee

router = APIRouter(prefix="/api/users", tags=["users"])

# Espejo de [Authorize(Roles = "Administrador,R_DITIC")] a nivel de clase en
# UsersController.cs.
_ADMIN_ROLES = ("Administrador", "R_DITIC")

_SORT_COLUMNS = {
    "email": User.email,
    "displayname": User.display_name,
    "usertype": User.user_type,
    "isactive": User.is_active,
    "lastlogin": User.last_login,
}


def _service(session: Session) -> CrudService[User, UserCreate, UserUpdate]:
    return CrudService(session, User)


def _snapshot(user: User) -> str:
    return json.dumps(
        {
            "email": user.email,
            "displayName": user.display_name,
            "isActive": user.is_active,
            "userType": user.user_type,
        }
    )


@router.get("")
def list_users(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(UserRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/paged")
def get_paged_users(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    sort_by: str | None = Query(default=None, alias="sortBy"),
    sort_direction: str = Query(default="asc", alias="sortDirection"),
    search: str | None = None,
    is_active: bool | None = Query(default=None, alias="isActive"),
    user_type: str | None = Query(default=None, alias="userType"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo EXACTO de UsersController.GetPaged: el endpoint que en realidad
    consume HrFrontend (a diferencia de List, filtra por texto/estado/tipo y
    ordena por 5 columnas). Orden por defecto: LastLogin descendente."""
    req = PagedRequest(
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_direction=sort_direction,
        search=search,
    )
    sort_key = (req.sort_by or "lastlogin").lower()
    # Espejo exacto de ApplyUserSorting: "lastlogin" es descendente salvo que
    # pidan "asc" explicito; cualquier otra columna es ascendente salvo que
    # pidan "desc" explicito. OJO: el comentario original en .NET dice "orden
    # predeterminado: ultimo login descendente", pero SortDirection por
    # defecto es "asc" (no None) — sin `sortDirection=desc` explicito en la
    # query, el orden real sin parametros es ASCENDENTE. Se replica el
    # comportamiento real del codigo, no lo que dice el comentario.
    desc = req.sort_direction != "asc" if sort_key == "lastlogin" else req.sort_direction == "desc"

    # User SI implementa ISoftDeletable en .NET: el HasQueryFilter automatico
    # de EF Core excluye IsDeleted=true incluso en esta query cruda de
    # GetPaged — se replica aqui a mano (GenericRepository ya lo hace para
    # List, pero este endpoint arma su propio select()).
    filters = [~User.is_deleted]
    if req.search:
        like = f"%{req.search}%"
        filters.append(or_(User.email.contains(like), User.display_name.contains(like)))
    if is_active is not None:
        filters.append(User.is_active == is_active)
    if user_type:
        filters.append(User.user_type == user_type)

    total_count = session.scalar(select(func.count()).select_from(User).where(*filters)) or 0

    column = _SORT_COLUMNS.get(sort_key, User.last_login)
    stmt = (
        select(User)
        .where(*filters)
        .order_by(column.desc() if desc else column.asc())
        .offset((req.page - 1) * req.page_size)
        .limit(req.page_size)
    )
    items = list(session.scalars(stmt))

    return ApiResponse.ok(
        {
            "items": [dump(UserRead.model_validate(item)) for item in items],
            "page": req.page,
            "pageSize": req.page_size,
            "totalCount": total_count,
        }
    )


@router.get("/{user_id}/permissions")
def get_user_permissions(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    permissions = user_permission_service.get_user_permissions(session, user_id)
    return ApiResponse.ok(dump(permissions), "Permisos obtenidos exitosamente")


@router.get("/{user_id}")
def get_user(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(user_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserRead.model_validate(entity)))


@router.post("")
def create_user(
    dto: UserCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo de UsersController.Create: crea User+UserEmployee en un solo
    paso via create_user_with_employee (que ya hace sus propias validaciones
    de duplicado, sin pre-consultar aqui para evitar una query redundante)."""
    if dto.user_type == "AzureAD" and dto.hr_employee_id <= 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="HrEmployeeId es obligatorio y debe ser un identificador de empleado valido.",
        )

    user, user_employee = create_user_with_employee(session, dto)
    read_user = UserRead.model_validate(user)
    read_employee = UserEmployeeRead.model_validate(user_employee)

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="UserCreated",
            module="Users",
            new_values=json.dumps(
                {"user": dump(read_user), "userEmployee": dump(read_employee)}
            ),
        )
    )
    return ApiResponse.ok({"user": dump(read_user), "userEmployee": dump(read_employee)})


@router.put("/{user_id}")
def update_user(
    user_id: UUID,
    dto: UserUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    service = _service(session)
    before = service.get(user_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    before_snapshot = _snapshot(before)

    updated = service.update(user_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="UserUpdated",
            module="Users",
            entity_id=str(user_id),
            old_values=before_snapshot,
            new_values=_snapshot(updated),
        )
    )
    return ApiResponse.ok(dump(UserRead.model_validate(updated)))


@router.delete("/{user_id}")
def delete_user(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo EXACTO de UsersController.Delete: borrado real en cascada (NO el
    soft-delete generico de CrudService, aunque User si implementa
    ISoftDeletable) sobre 8 tablas relacionadas, con snapshot de auditoria
    antes de borrar. La cascada vive en UserRepository.delete_with_cascade
    (Fase 3); este router solo la invoca."""
    entity = _service(session).get(user_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    snapshot = _snapshot(entity)

    UserRepository(session).delete_with_cascade(user_id)
    session.flush()

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="UserDeleted", module="Users", entity_id=str(user_id), old_values=snapshot
        )
    )
    return ApiResponse.ok(message="Eliminado")
