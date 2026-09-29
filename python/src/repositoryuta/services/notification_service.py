import hashlib
import hmac
import json
import logging
import time
from datetime import datetime
from uuid import UUID

import requests
from sqlalchemy.orm import Session

from repositoryuta.models.application import Application
from repositoryuta.models.identity import User
from repositoryuta.models.notification import NotificationLog, NotificationSubscription
from repositoryuta.models.rbac import Permission, Role, RolePermission, UserRole
from repositoryuta.repositories.notification_repository import NotificationRepository
from repositoryuta.schemas.auth import TokenPair
from repositoryuta.schemas.notification import (
    NotificationLogCreate,
    NotificationStatsRead,
    SubscriptionStatsRead,
)

logger = logging.getLogger(__name__)

# Espejo de NotificationService.cs. Alcance de esta migracion (decision
# explicita del usuario, 2026-08-28): SOLO el CRUD de suscripciones y la
# entrega por webhook saliente. La entrega por SignalR/WebSocket ("websocket"/
# "both") NO se reconstruye — el unico caso real donde se usa (login de Azure,
# ver auth.tbl_NotificationSubscriptions en produccion) ya esta cubierto
# funcionalmente por el postMessage aditivo de routers/auth.py::azure_callback.
# Para esos tipos de suscripcion, aqui simplemente se omite esa rama con un log,
# en vez de intentar un hub SignalR/WebSocket generico que no tiene otro
# consumidor real hoy.


# ── Suscripciones (CRUD) ──────────────────────────────────────────────────────


def create_subscription(
    session: Session,
    application_id: UUID,
    event_type: str,
    webhook_url: str,
    secret_key: str | None,
) -> UUID:
    app_exists = (
        session.query(Application)
        .filter(
            Application.id == application_id,
            Application.is_active,
            ~Application.is_deleted,
        )
        .first()
        is not None
    )
    if not app_exists:
        raise ValueError("Application not found or inactive")

    subscription = NotificationSubscription(
        application_id=application_id, event_type=event_type, webhook_url=webhook_url,
        secret_key=secret_key,
    )
    session.add(subscription)
    session.commit()

    logger.info(
        "Suscripción creada: %s para aplicación %s", subscription.id, application_id
    )
    return subscription.id


def update_subscription(
    session: Session,
    subscription_id: UUID,
    webhook_url: str | None,
    secret_key: str | None,
    is_active: bool | None,
) -> bool:
    try:
        subscription = session.get(NotificationSubscription, subscription_id)
        if subscription is None:
            return False

        if webhook_url:
            subscription.webhook_url = webhook_url
        if secret_key is not None:
            subscription.secret_key = secret_key
        if is_active is not None:
            subscription.is_active = is_active

        session.commit()
        return True
    except Exception:
        logger.exception("Error actualizando suscripción %s", subscription_id)
        return False


def delete_subscription(session: Session, subscription_id: UUID) -> bool:
    try:
        subscription = session.get(NotificationSubscription, subscription_id)
        if subscription is None:
            return False

        session.delete(subscription)
        session.commit()
        return True
    except Exception:
        logger.exception("Error eliminando suscripción %s", subscription_id)
        return False


def get_subscriptions_by_application(
    session: Session, application_id: UUID
) -> list[NotificationSubscription]:
    return (
        session.query(NotificationSubscription)
        .filter(
            NotificationSubscription.application_id == application_id,
            NotificationSubscription.is_active,
        )
        .all()
    )


# ── Estadísticas ──────────────────────────────────────────────────────────────


def get_notification_stats(session: Session) -> NotificationStatsRead:
    total_subscriptions = session.query(NotificationSubscription).count()
    active_subscriptions = (
        session.query(NotificationSubscription)
        .filter(NotificationSubscription.is_active)
        .count()
    )
    total_logs = session.query(NotificationLog).count()
    successful_logs = (
        session.query(NotificationLog).filter(NotificationLog.is_success).count()
    )
    failed_logs = (
        session.query(NotificationLog).filter(~NotificationLog.is_success).count()
    )

    return NotificationStatsRead(
        total_subscriptions=total_subscriptions,
        active_subscriptions=active_subscriptions,
        total_logs=total_logs,
        successful_logs=successful_logs,
        failed_notifications=failed_logs,
    )


def get_subscription_stats(
    session: Session, application_id: UUID
) -> list[SubscriptionStatsRead]:
    subscriptions = (
        session.query(NotificationSubscription)
        .filter(NotificationSubscription.application_id == application_id)
        .all()
    )

    results = []
    for s in subscriptions:
        logs = session.query(NotificationLog).filter(NotificationLog.subscription_id == s.id).all()
        successful = sum(1 for log_ in logs if log_.is_success)
        results.append(
            SubscriptionStatsRead(
                subscription_id=s.id,
                event_type=s.event_type,
                webhook_url=s.webhook_url or "",
                is_active=s.is_active,
                total_notifications=len(logs),
                successful_notifications=successful,
                failed_notifications=len(logs) - successful,
                last_modified=s.modified_at,
            )
        )
    return results


def process_pending_notifications() -> None:
    """Espejo de ProcessPendingNotificationsAsync: las notificaciones se envían
    directamente (no hay cola pendiente que procesar), igual que el .NET real."""
    logger.info("ProcessPendingNotificationsAsync: las notificaciones se envían directamente")


# ── Eventos (entrega por webhook) ─────────────────────────────────────────────


def notify_login_event_for_application(
    session: Session,
    user_id: UUID,
    login_type: str,
    ip_address: str | None,
    client_id: str,
    pair: TokenPair | None,
    browser_id: str,
    delivery_code: str | None = None,
) -> None:
    try:
        application = (
            session.query(Application)
            .filter(
                Application.client_id == client_id,
                Application.is_active,
                ~Application.is_deleted,
            )
            .first()
        )
        if application is None:
            logger.warning("Aplicación con clientId %s no encontrada", client_id)
            return

        subscriptions = (
            session.query(NotificationSubscription)
            .filter(
                NotificationSubscription.application_id == application.id,
                NotificationSubscription.event_type == "Login",
                NotificationSubscription.is_active,
            )
            .all()
        )
        if not subscriptions:
            return

        event_data = _prepare_login_event_data(
            session, user_id, login_type, ip_address, client_id, pair, delivery_code
        )
        if event_data is None:
            return

        for subscription in subscriptions:
            notification_type = (subscription.notification_type or "webhook").lower()
            if notification_type in ("webhook", "both"):
                _send_webhook(session, subscription, "Login", event_data)
            if notification_type in ("websocket", "both"):
                logger.info(
                    "Entrega 'websocket' de la suscripción %s omitida a propósito — "
                    "reemplazada por el postMessage del popup de login "
                    "(routers/auth.py::azure_callback); no se reconstruyó un hub "
                    "SignalR/WebSocket genérico en Python.",
                    subscription.id,
                )

        logger.info(
            "Notificaciones enviadas para usuario %s a aplicación %s", user_id, client_id
        )
    except Exception:
        logger.exception("Error al enviar notificaciones a %s", client_id)


def notify_login_event(
    session: Session,
    user_id: UUID,
    login_type: str,
    ip_address: str | None,
    roles: list[str] | None,
    permissions: list[dict] | None,
    pair: TokenPair | None,
    browser_id: str,
) -> None:
    try:
        user = session.get(User, user_id)
        if user is None:
            return

        event_data = {
            "userId": str(user_id),
            "email": user.email,
            "displayName": user.display_name,
            "loginType": login_type,
            "ipAddress": ip_address or "",
            "loginTime": datetime.now().isoformat(),
            "roles": roles,
            "permissions": permissions,
            "pair": pair.model_dump(by_alias=True, mode="json") if pair else None,
        }
        _send_direct_notifications(session, "Login", event_data)
        logger.info("Notificación de login enviada para usuario %s", user_id)
    except Exception:
        logger.exception("Error enviando notificación de login para usuario %s", user_id)


def notify_logout_event(session: Session, user_id: UUID) -> None:
    try:
        user = session.get(User, user_id)
        if user is None:
            return

        event_data = {
            "userId": str(user_id), "email": user.email,
            "logoutTime": datetime.now().isoformat(),
        }
        _send_direct_notifications(session, "Logout", event_data)
        logger.info("Notificación de logout enviada para usuario %s", user_id)
    except Exception:
        logger.exception("Error enviando notificación de logout para usuario %s", user_id)


def notify_user_created_event(session: Session, user_id: UUID) -> None:
    try:
        user = session.get(User, user_id)
        if user is None:
            return

        event_data = {
            "userId": str(user_id), "email": user.email, "displayName": user.display_name,
            "userType": user.user_type, "createdAt": user.created_at.isoformat(),
        }
        _send_direct_notifications(session, "UserCreated", event_data)
        logger.info("Notificación de usuario creado enviada para %s", user_id)
    except Exception:
        logger.exception("Error enviando notificación de usuario creado para %s", user_id)


# ── Helpers internos ──────────────────────────────────────────────────────────


def _prepare_login_event_data(
    session: Session,
    user_id: UUID,
    login_type: str,
    ip_address: str | None,
    client_id: str,
    pair: TokenPair | None,
    delivery_code: str | None,
) -> dict | None:
    user = session.get(User, user_id)
    if user is None:
        return None

    roles = _get_user_roles(session, user_id)
    permissions = _get_user_permissions(session, user_id)

    return {
        "eventType": "Login",
        "timestamp": datetime.now().isoformat(),
        "context": {
            "initiatingApplication": client_id,
            "loginSource": login_type,
            "sessionScope": "specific",
            "notificationType": "hybrid",
        },
        "data": {
            "userId": str(user_id),
            "email": user.email,
            "displayName": user.display_name,
            "loginType": login_type,
            "ipAddress": ip_address,
            "roles": roles,
            "permissions": permissions,
        },
        # PKCE: cuando hay deliveryCode, el par de tokens real NO viaja en el
        # payload de webhook — solo la referencia de un solo uso, canjeable en
        # POST /api/auth/azure/exchange.
        "pair": (
            None
            if delivery_code
            else (pair.model_dump(by_alias=True, mode="json") if pair else None)
        ),
        "deliveryCode": delivery_code,
    }


def _get_user_roles(session: Session, user_id: UUID) -> list[str]:
    rows = (
        session.query(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id, ~UserRole.is_deleted)
        .all()
    )
    return [name for (name,) in rows]


def _get_user_permissions(session: Session, user_id: UUID) -> list[dict]:
    rows = (
        session.query(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .filter(UserRole.user_id == user_id, ~UserRole.is_deleted)
        .filter(~Permission.is_deleted)
        .distinct()
        .all()
    )
    return [
        {"id": p.id, "name": p.name, "module": p.module, "action": p.action,
         "description": p.description}
        for p in rows
    ]


def _send_direct_notifications(session: Session, event_type: str, event_data: dict) -> None:
    subscriptions = (
        session.query(NotificationSubscription)
        .filter(
            NotificationSubscription.event_type == event_type,
            NotificationSubscription.is_active,
        )
        .all()
    )
    for subscription in subscriptions:
        _send_webhook(session, subscription, event_type, event_data)


def _send_webhook(
    session: Session, subscription: NotificationSubscription, event_type: str, event_data: dict
) -> None:
    if not subscription.webhook_url:
        return

    start = time.monotonic()
    try:
        payload = json.dumps(event_data)
        headers = {"Content-Type": "application/json"}
        if subscription.secret_key:
            headers["X-Webhook-Signature"] = _generate_signature(payload, subscription.secret_key)

        response = requests.post(
            subscription.webhook_url, data=payload, headers=headers, timeout=30
        )
        _log_notification(
            session, subscription.id, event_type, subscription.webhook_url,
            response.status_code, response.text, start, response.ok,
            None if response.ok else f"HTTP {response.status_code}: {response.text}",
        )
        logger.info(
            "Webhook enviado a %s con status %s", subscription.webhook_url, response.status_code
        )
    except Exception as exc:
        _log_notification(
            session, subscription.id, event_type, subscription.webhook_url, 0, None, start,
            False, str(exc),
        )
        logger.error("Error enviando webhook a %s: %s", subscription.webhook_url, exc)


def _log_notification(
    session: Session,
    subscription_id: UUID,
    event_type: str,
    webhook_url: str | None,
    http_status_code: int,
    response_body: str | None,
    start: float,
    is_success: bool,
    error_message: str | None,
) -> None:
    NotificationRepository(session).log_notification(
        NotificationLogCreate(
            subscription_id=subscription_id,
            event_type=event_type,
            webhook_url=webhook_url,
            http_status_code=http_status_code,
            response_body=response_body,
            is_success=is_success,
            response_time=int((time.monotonic() - start) * 1000),
            error_message=error_message,
        )
    )
    session.commit()


def _generate_signature(payload: str, secret_key: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
