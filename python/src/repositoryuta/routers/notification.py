from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.notification import (
    NotificationSubscriptionCreate,
    NotificationSubscriptionRead,
    NotificationSubscriptionUpdate,
)
from repositoryuta.services import notification_service

# Espejo de NotificationController.cs. Alcance de esta migracion (ver
# notification_service.py): CRUD de suscripciones + entrega por webhook
# saliente. La entrega por SignalR/WebSocket no se reconstruye — ver nota en
# el servicio.
router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.post("/subscriptions")
def create_subscription(
    req: NotificationSubscriptionCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    try:
        subscription_id = notification_service.create_subscription(
            session, req.application_id, req.event_type, req.webhook_url, req.secret_key
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ApiResponse.ok(
        {"subscriptionId": str(subscription_id)}, "Subscription created successfully"
    )


@router.put("/subscriptions/{subscription_id}")
def update_subscription(
    subscription_id: UUID,
    req: NotificationSubscriptionUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    success = notification_service.update_subscription(
        session, subscription_id, req.webhook_url, req.secret_key, req.is_active
    )
    if not success:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return ApiResponse.ok(None, "Subscription updated successfully")


@router.delete("/subscriptions/{subscription_id}")
def delete_subscription(
    subscription_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    success = notification_service.delete_subscription(session, subscription_id)
    if not success:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return ApiResponse.ok(None, "Subscription deleted successfully")


@router.get("/subscriptions/application/{application_id}")
def get_subscriptions_by_application(
    application_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    subscriptions = notification_service.get_subscriptions_by_application(session, application_id)
    return ApiResponse.ok(
        [dump(NotificationSubscriptionRead.model_validate(s)) for s in subscriptions],
        "Subscriptions retrieved successfully",
    )


@router.get("/stats")
def get_notification_stats(
    session: Session = Depends(get_db_session), _actor_id: UUID = Depends(get_current_user_id)
) -> ApiResponse:
    stats = notification_service.get_notification_stats(session)
    return ApiResponse.ok(dump(stats), "Notification statistics retrieved")


@router.get("/stats/application/{application_id}")
def get_subscription_stats(
    application_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    stats = notification_service.get_subscription_stats(session, application_id)
    return ApiResponse.ok([dump(s) for s in stats], "Subscription statistics retrieved")


@router.post("/process-pending")
def process_pending_notifications(
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    notification_service.process_pending_notifications()
    return ApiResponse.ok(None, "Pending notifications processed")


@router.post("/webhook-test")
def webhook_test(payload: Any = Body(default=None)) -> dict:
    """[AllowAnonymous] en el .NET original — endpoint de prueba para que un
    tercero valide que su URL de webhook responde, no expone datos propios."""
    return {
        "Status": "Success",
        "Message": "Webhook received successfully",
        "Timestamp": datetime.now().isoformat(),
        "ReceivedPayload": payload,
    }
