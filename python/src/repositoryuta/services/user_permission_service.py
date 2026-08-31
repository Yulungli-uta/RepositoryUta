from uuid import UUID

from sqlalchemy.orm import Session

from repositoryuta.repositories.user_permission_repository import UserPermissionRepository
from repositoryuta.schemas.audit import MenuItemRead, UserPermissionsRead, UserRoleRead

# Espejo de UserPermissionService.cs: roles + menus + permisos (derivados de
# las URLs del menu) de un usuario. Sin Task.WhenAll deliberado en el .NET
# real (comentario propio del autor: "no romper el DbContext" al paralelizar
# dos queries sobre el mismo contexto) — aqui es secuencial de por si, una
# Session de SQLAlchemy tampoco es segura para queries concurrentes.


def get_user_roles(session: Session, user_id: UUID) -> list[UserRoleRead]:
    rows = UserPermissionRepository(session).get_user_roles(user_id)
    return [UserRoleRead.model_validate(row) for row in rows]


def get_user_menu_items(session: Session, user_id: UUID) -> list[MenuItemRead]:
    rows = UserPermissionRepository(session).get_user_menu_items(user_id)
    return [MenuItemRead.model_validate(row) for row in rows]


def _urls_from_menu_items(menu_items: list[MenuItemRead]) -> list[str]:
    return sorted({item.url for item in menu_items if item.url})


def get_user_permissions_urls(session: Session, user_id: UUID) -> list[str]:
    menu_items = get_user_menu_items(session, user_id)
    return _urls_from_menu_items(menu_items)


def get_user_permissions(session: Session, user_id: UUID) -> UserPermissionsRead:
    roles = get_user_roles(session, user_id)
    menu_items = get_user_menu_items(session, user_id)
    return UserPermissionsRead(
        roles=roles,
        permissions=_urls_from_menu_items(menu_items),
        menu_items=menu_items,
    )
