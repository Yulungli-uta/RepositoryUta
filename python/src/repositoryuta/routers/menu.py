from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.menu_service import get_menu_for_user

router = APIRouter(prefix="/api/menu", tags=["menu"])


@router.get("/user")
def get_menu(
    user_id: UUID = Depends(get_current_user_id),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """Espejo de MenuController.GetByUser."""
    items = get_menu_for_user(session, user_id)
    return ApiResponse.ok([dump(item) for item in items])
