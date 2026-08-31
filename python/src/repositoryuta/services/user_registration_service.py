import logging
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.exceptions import ConflictError
from repositoryuta.models.identity import User, UserEmployee
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.schemas.identity import UserCreate

logger = logging.getLogger(__name__)


def create_user_with_employee(session: Session, data: UserCreate) -> tuple[User, UserEmployee]:
    """Espejo de UserRegistrationService.CreateUserWithEmployeeAsync: crea User
    y UserEmployee como una sola unidad de trabajo, con las mismas 2
    validaciones de duplicado (email en Users Y en UserEmployees) y la regla
    de HrEmployeeId (>0 se guarda, si no queda NULL — nunca 0 falso, ver
    comentario original sobre "cuentas locales sin empleado real").

    La transaccion (commit/rollback) la maneja quien llame esto via
    `session_scope()` — este servicio no hace commit por si mismo.

    Diferencia deliberada vs. .NET: el duplicado se reporta como ConflictError
    (409) en vez de dejarlo caer a una excepcion no controlada — .NET no
    distingue este caso en ErrorHandlerMiddleware, cae a un 500 generico. Es
    una mejora de semantica HTTP sin cambiar seguridad ni datos expuestos.
    """
    email = data.email.strip()
    repo = UserRepository(session)

    if repo.find_by_email(email) is not None:
        raise ConflictError("Ya existe un usuario con ese email.")

    existing_employee = session.scalar(
        select(UserEmployee).where(UserEmployee.employee_email == email)
    )
    if existing_employee is not None:
        raise ConflictError("Ya existe un UserEmployee con ese email.")

    user = User(
        id=uuid4(),
        email=email,
        display_name=data.display_name,
        user_type=data.user_type,
        is_active=True,
        created_at=datetime.now(),
    )
    session.add(user)
    session.flush()

    user_employee = UserEmployee(
        user_id=user.id,
        employee_email=email,
        hr_employee_id=data.hr_employee_id if data.hr_employee_id > 0 else None,
        is_active=True,
        sync_date=datetime.now(),
        notes="Creado manualmente desde el panel de administracion",
    )
    session.add(user_employee)
    session.flush()

    logger.info("Usuario %s creado correctamente con email %s", user.id, email)
    return user, user_employee
